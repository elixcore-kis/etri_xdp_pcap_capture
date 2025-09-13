#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <poll.h>

// PCAP file format structures
struct pcap_file_header {
    __u32 magic;
    __u16 version_major;
    __u16 version_minor;
    __s32 thiszone;
    __u32 sigfigs;
    __u32 snaplen;
    __u32 linktype;
};

struct pcap_pkthdr {
    struct {
        __u32 tv_sec;
        __u32 tv_usec;
    } ts;
    __u32 caplen;
    __u32 len;
};

// AF_XDP constants
#define FRAME_SIZE 4096
#define NUM_FRAMES 2048
#define BATCH_SIZE 64

struct xdp_ring_offset_v1 {
    __u64 producer;
    __u64 consumer;
    __u64 desc;
    __u64 flags;
};

struct xdp_mmap_offsets_v1 {
    struct xdp_ring_offset_v1 rx;
    struct xdp_ring_offset_v1 tx;
    struct xdp_ring_offset_v1 fr; /* Fill */
    struct xdp_ring_offset_v1 cr; /* Completion */
};

struct xsk_ring_prod {
    __u32 cached_prod;
    __u32 cached_cons;
    __u32 mask;
    __u32 size;
    __u32 *producer;
    __u32 *consumer;
    void *ring;
    __u32 *flags;
};

struct xsk_ring_cons {
    __u32 cached_prod;
    __u32 cached_cons;
    __u32 mask;
    __u32 size;
    __u32 *producer;
    __u32 *consumer;
    void *ring;
    __u32 *flags;
};

struct xsk_umem {
    void *umem_area;
    size_t size;
    int fd;
};

struct xsk_socket {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod fq;
    struct xsk_ring_prod cq;
    struct xsk_umem *umem;
    int fd;
    __u32 ifindex;
    __u32 queue_id;
};

static volatile int keep_running = 1;
static FILE *output_file_ptr = NULL;
static int packet_count = 0;
static int prog_fd_global = -1;
static int src_ifindex_global = 0;
static int stats_map_fd = -1;

void signal_handler(int sig) {
    (void)sig;
    keep_running = 0;
    printf("\\nReceived signal %d, stopping...\\n", sig);
}

void cleanup() {
    if (prog_fd_global >= 0 && src_ifindex_global > 0) {
        printf("Detaching XDP program from interface...\\n");
        bpf_xdp_detach(src_ifindex_global, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    }
    
    if (output_file_ptr) {
        fclose(output_file_ptr);
        printf("Captured %d packets total\\n", packet_count);
    }
}

static void write_pcap_header(FILE *file) {
    struct pcap_file_header hdr = {
        .magic = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,  // No size limit with AF_XDP
        .linktype = 1  // Ethernet
    };
    fwrite(&hdr, sizeof(hdr), 1, file);
    fflush(file);
}

static int xsk_configure_umem(struct xsk_umem *umem, void *buffer, __u64 size, int fd) {
    struct xdp_umem_reg mr;

    umem->umem_area = buffer;
    umem->size = size;
    umem->fd = fd;

    mr.addr = (__u64)buffer;
    mr.len = size;
    mr.chunk_size = FRAME_SIZE;
    mr.headroom = 0;
    mr.flags = 0;
    mr.tx_metadata_len = 0;

    return setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));
}

static int xsk_configure_socket(struct xsk_socket *xsk, struct xsk_umem *umem, 
                               const char *ifname, __u32 queue_id) {
    struct sockaddr_xdp sxdp = {};
    struct xdp_mmap_offsets_v1 off;
    socklen_t optlen;
    void *rx_map, *tx_map;
    int ret;

    xsk->umem = umem;
    xsk->ifindex = if_nametoindex(ifname);
    xsk->queue_id = queue_id;

    if (xsk->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\\n", ifname);
        return -1;
    }

    xsk->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk->fd < 0) {
        perror("socket");
        return -1;
    }

    // Configure rings
    __u32 fq_size = NUM_FRAMES, cq_size = NUM_FRAMES;
    __u32 rx_size = NUM_FRAMES, tx_size = NUM_FRAMES;

    ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size, sizeof(__u32));
    if (ret < 0) {
        perror("setsockopt(XDP_UMEM_FILL_RING)");
        close(xsk->fd);
        return -1;
    }

    ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cq_size, sizeof(__u32));
    if (ret < 0) {
        perror("setsockopt(XDP_UMEM_COMPLETION_RING)");
        close(xsk->fd);
        return -1;
    }

    ret = setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &rx_size, sizeof(__u32));
    if (ret < 0) {
        perror("setsockopt(XDP_RX_RING)");
        close(xsk->fd);
        return -1;
    }

    ret = setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING, &tx_size, sizeof(__u32));
    if (ret < 0) {
        perror("setsockopt(XDP_TX_RING)");
        close(xsk->fd);
        return -1;
    }

    // Get mmap offsets
    optlen = sizeof(off);
    ret = getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen);
    if (ret < 0) {
        perror("getsockopt(XDP_MMAP_OFFSETS)");
        close(xsk->fd);
        return -1;
    }

    // Memory map rings
    rx_map = mmap(NULL, off.rx.desc + NUM_FRAMES * sizeof(struct xdp_desc),
                  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, 
                  xsk->fd, XDP_PGOFF_RX_RING);
    if (rx_map == MAP_FAILED) {
        perror("mmap(XDP_PGOFF_RX_RING)");
        close(xsk->fd);
        return -1;
    }

    tx_map = mmap(NULL, off.fr.desc + NUM_FRAMES * sizeof(__u64),
                  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                  xsk->fd, XDP_PGOFF_TX_RING);
    if (tx_map == MAP_FAILED) {
        perror("mmap(XDP_PGOFF_TX_RING)");
        munmap(rx_map, off.rx.desc + NUM_FRAMES * sizeof(struct xdp_desc));
        close(xsk->fd);
        return -1;
    }

    // Setup rings
    xsk->rx.mask = NUM_FRAMES - 1;
    xsk->rx.size = NUM_FRAMES;
    xsk->rx.cached_cons = 0;
    xsk->rx.cached_prod = 0;
    xsk->rx.producer = (void *)((char *)rx_map + off.rx.producer);
    xsk->rx.consumer = (void *)((char *)rx_map + off.rx.consumer);
    xsk->rx.flags = (void *)((char *)rx_map + off.rx.flags);
    xsk->rx.ring = (void *)((char *)rx_map + off.rx.desc);

    xsk->fq.mask = NUM_FRAMES - 1;
    xsk->fq.size = NUM_FRAMES;
    xsk->fq.cached_cons = 0;
    xsk->fq.cached_prod = NUM_FRAMES;  // Initialize with filled frames
    xsk->fq.producer = (void *)((char *)tx_map + off.fr.producer);
    xsk->fq.consumer = (void *)((char *)tx_map + off.fr.consumer);
    xsk->fq.flags = (void *)((char *)tx_map + off.fr.flags);
    xsk->fq.ring = (void *)((char *)tx_map + off.fr.desc);

    // Bind socket
    sxdp.sxdp_family = AF_XDP;
    sxdp.sxdp_ifindex = xsk->ifindex;
    sxdp.sxdp_queue_id = queue_id;
    sxdp.sxdp_flags = XDP_ZEROCOPY;

    ret = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
    if (ret) {
        // Try copy mode
        sxdp.sxdp_flags = XDP_COPY;
        ret = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
        if (ret) {
            perror("bind");
            munmap(rx_map, off.rx.desc + NUM_FRAMES * sizeof(struct xdp_desc));
            munmap(tx_map, off.fr.desc + NUM_FRAMES * sizeof(__u64));
            close(xsk->fd);
            return -1;
        }
        printf("AF_XDP: Using copy mode\\n");
    } else {
        printf("AF_XDP: Using zero-copy mode\\n");
    }

    // Populate fill ring
    __u32 idx = 0;
    for (int i = 0; i < NUM_FRAMES; i++) {
        *((__u64 *)xsk->fq.ring + (idx & xsk->fq.mask)) = i * FRAME_SIZE;
        idx++;
    }
    
    // Make sure fill ring updates are visible
    __sync_synchronize();
    *xsk->fq.producer = idx;

    return 0;
}

static void process_packets(struct xsk_socket *xsk, FILE *output_file) {
    struct pollfd fds[1];
    fds[0].fd = xsk->fd;
    fds[0].events = POLLIN;

    while (keep_running) {
        int ret = poll(fds, 1, 1000);
        if (ret <= 0) continue;

        __u32 idx_rx = xsk->rx.cached_cons;
        __u32 idx_fq = xsk->fq.cached_prod;
        
        int rcvd = *xsk->rx.producer - xsk->rx.cached_cons;
        if (rcvd == 0) continue;

        if (rcvd > BATCH_SIZE) rcvd = BATCH_SIZE;

        for (int i = 0; i < rcvd; i++) {
            __u32 idx = (idx_rx++) & xsk->rx.mask;
            struct xdp_desc *desc = (struct xdp_desc *)xsk->rx.ring + idx;
            
            void *pkt_data = (char *)xsk->umem->umem_area + desc->addr;
            __u32 pkt_len = desc->len;
            
            // Write to PCAP file
            struct pcap_pkthdr pkt_hdr;
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            
            pkt_hdr.ts.tv_sec = ts.tv_sec;
            pkt_hdr.ts.tv_usec = ts.tv_nsec / 1000;
            pkt_hdr.caplen = pkt_len;  // Full packet length!
            pkt_hdr.len = pkt_len;
            
            fwrite(&pkt_hdr, sizeof(pkt_hdr), 1, output_file);
            fwrite(pkt_data, pkt_len, 1, output_file);
            
            packet_count++;
            
            // Return frame to fill queue
            *((__u64 *)xsk->fq.ring + ((idx_fq++) & xsk->fq.mask)) = desc->addr;
        }
        
        xsk->rx.cached_cons = idx_rx;
        xsk->fq.cached_prod = idx_fq;
        
        // Update kernel
        *xsk->rx.consumer = xsk->rx.cached_cons;
        *xsk->fq.producer = xsk->fq.cached_prod;
        
        if (rcvd > 0) {
            fflush(output_file);
            printf("\\rCaptured packets: %d", packet_count);
            fflush(stdout);
        }
    }
}

static void print_stats(int stats_fd) {
    if (stats_fd < 0) return;
    
    __u64 rx_packets = 0, captured = 0, dropped = 0, errors = 0;
    __u32 key;
    
    key = 0; bpf_map_lookup_elem(stats_fd, &key, &rx_packets);
    key = 1; bpf_map_lookup_elem(stats_fd, &key, &captured);
    key = 2; bpf_map_lookup_elem(stats_fd, &key, &dropped);
    key = 3; bpf_map_lookup_elem(stats_fd, &key, &errors);
    
    printf("\\nXDP Stats - RX: %llu, Captured: %llu, Dropped: %llu, Errors: %llu\\n",
           rx_packets, captured, dropped, errors);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <interface> <output.pcap>\\n", argv[0]);
        printf("Example: %s ens18 capture.pcap\\n", argv[0]);
        return 1;
    }
    
    const char *ifname = argv[1];
    const char *output_filename = argv[2];
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    atexit(cleanup);
    
    // Open output file
    output_file_ptr = fopen(output_filename, "wb");
    if (!output_file_ptr) {
        perror("fopen");
        return 1;
    }
    write_pcap_header(output_file_ptr);
    
    // Load XDP program
    struct bpf_object *obj = bpf_object__open("xdp_afxdp.o");
    if (!obj) {
        fprintf(stderr, "Failed to open XDP object file\\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load XDP program\\n");
        bpf_object__close(obj);
        return 1;
    }
    
    prog_fd_global = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_afxdp_redirect"));
    if (prog_fd_global < 0) {
        fprintf(stderr, "Failed to find XDP program\\n");
        bpf_object__close(obj);
        return 1;
    }
    
    int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    
    // Setup UMEM
    struct xsk_umem umem;
    void *umem_area = mmap(NULL, NUM_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (umem_area == MAP_FAILED) {
        perror("mmap UMEM");
        bpf_object__close(obj);
        return 1;
    }
    
    // Create AF_XDP socket
    struct xsk_socket xsk;
    if (xsk_configure_umem(&umem, umem_area, NUM_FRAMES * FRAME_SIZE, -1) < 0) {
        fprintf(stderr, "Failed to configure UMEM\\n");
        munmap(umem_area, NUM_FRAMES * FRAME_SIZE);
        bpf_object__close(obj);
        return 1;
    }
    
    if (xsk_configure_socket(&xsk, &umem, ifname, 0) < 0) {
        fprintf(stderr, "Failed to create AF_XDP socket\\n");
        munmap(umem_area, NUM_FRAMES * FRAME_SIZE);
        bpf_object__close(obj);
        return 1;
    }
    
    src_ifindex_global = xsk.ifindex;
    
    // Insert socket into map
    __u32 queue_id = 0;
    __u32 xsk_fd = xsk.fd;
    if (bpf_map_update_elem(xsks_map_fd, &queue_id, &xsk_fd, 0)) {
        perror("bpf_map_update_elem");
        close(xsk.fd);
        munmap(umem_area, NUM_FRAMES * FRAME_SIZE);
        bpf_object__close(obj);
        return 1;
    }
    
    // Attach XDP program
    if (bpf_xdp_attach(xsk.ifindex, prog_fd_global, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL)) {
        perror("bpf_xdp_attach");
        close(xsk.fd);
        munmap(umem_area, NUM_FRAMES * FRAME_SIZE);
        bpf_object__close(obj);
        return 1;
    }
    
    printf("AF_XDP packet capture started on %s\\n", ifname);
    printf("Output file: %s\\n", output_filename);
    printf("Press Ctrl+C to stop\\n\\n");
    
    // Start packet processing
    process_packets(&xsk, output_file_ptr);
    
    print_stats(stats_map_fd);
    printf("\\nShutting down...\\n");
    
    // Cleanup
    close(xsk.fd);
    munmap(umem_area, NUM_FRAMES * FRAME_SIZE);
    bpf_object__close(obj);
    
    return 0;
}