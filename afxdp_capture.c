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
#define NUM_FRAMES 4096
#define BATCH_SIZE 64

// AF_XDP ring structures (use system-defined xdp_desc)

struct xdp_ring {
    __u32 *producer;
    __u32 *consumer;
    __u32 *flags;
    struct xdp_desc *desc;
    void *map;
    __u32 size;
};

struct xdp_umem {
    void *buffer;
    size_t size;
    int fd;
};

struct afxdp_socket {
    int fd;
    struct xdp_ring rx;
    struct xdp_ring fq;  // Fill queue
    struct xdp_ring cq;  // Completion queue
    struct xdp_umem umem;
    __u32 ifindex;
    __u32 queue_id;
};

static volatile int keep_running = 1;
static int src_ifindex_global = 0;
static int prog_fd_global = -1;
static FILE *output_file_ptr = NULL;
static int packet_count = 0;
static int stats_map_fd = -1;

void signal_handler(int sig) {
    (void)sig;
    keep_running = 0;
    printf("\nReceived signal %d, stopping...\n", sig);
}

void cleanup() {
    if (prog_fd_global >= 0 && src_ifindex_global > 0) {
        printf("Detaching XDP program from interface...\n");
        bpf_xdp_detach(src_ifindex_global, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    }
    
    if (output_file_ptr) {
        fclose(output_file_ptr);
        printf("Captured %d packets total\n", packet_count);
    }
}

static int xdp_ring_init(struct xdp_ring *ring, void *map_ptr, __u64 ring_offset, __u32 ring_size) {
    ring->map = map_ptr;
    ring->size = ring_size;
    ring->producer = (void*)((char*)map_ptr + ring_offset);
    ring->consumer = (void*)((char*)map_ptr + ring_offset + sizeof(__u32));
    ring->flags = (void*)((char*)map_ptr + ring_offset + 2 * sizeof(__u32));
    ring->desc = (void*)((char*)map_ptr + ring_offset + sizeof(struct xdp_ring_offset));
    return 0;
}

static int create_af_xdp_socket(struct afxdp_socket *xsk, const char *ifname, __u32 queue_id) {
    struct sockaddr_xdp sxdp = {};
    struct xdp_mmap_offsets off;
    struct xdp_umem_reg umem_reg;
    socklen_t optlen;
    void *umem_area, *rx_map, *fq_map, *cq_map;
    int ret;

    // Get interface index
    xsk->ifindex = if_nametoindex(ifname);
    if (xsk->ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", ifname);
        return -1;
    }
    xsk->queue_id = queue_id;

    // Create socket
    xsk->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk->fd < 0) {
        perror("socket");
        return -1;
    }

    // Allocate UMEM
    xsk->umem.size = NUM_FRAMES * FRAME_SIZE;
    umem_area = mmap(NULL, xsk->umem.size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (umem_area == MAP_FAILED) {
        perror("mmap UMEM");
        close(xsk->fd);
        return -1;
    }
    xsk->umem.buffer = umem_area;

    // Register UMEM
    umem_reg.addr = (__u64)umem_area;
    umem_reg.len = xsk->umem.size;
    umem_reg.chunk_size = FRAME_SIZE;
    umem_reg.headroom = 0;
    umem_reg.flags = 0;

    ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg));
    if (ret) {
        perror("setsockopt XDP_UMEM_REG");
        goto cleanup;
    }

    // Setup Fill Queue
    __u32 fq_size = NUM_FRAMES;
    ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size, sizeof(__u32));
    if (ret) {
        perror("setsockopt XDP_UMEM_FILL_RING");
        goto cleanup;
    }

    // Setup Completion Queue  
    __u32 cq_size = NUM_FRAMES;
    ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cq_size, sizeof(__u32));
    if (ret) {
        perror("setsockopt XDP_UMEM_COMPLETION_RING");
        goto cleanup;
    }

    // Setup RX Ring
    __u32 rx_size = NUM_FRAMES;
    ret = setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &rx_size, sizeof(__u32));
    if (ret) {
        perror("setsockopt XDP_RX_RING");
        goto cleanup;
    }

    // Get memory map offsets
    optlen = sizeof(off);
    ret = getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen);
    if (ret) {
        perror("getsockopt XDP_MMAP_OFFSETS");
        goto cleanup;
    }

    // Memory map rings with correct sizes and offsets
    size_t rx_map_size = off.rx.desc + NUM_FRAMES * sizeof(struct xdp_desc);
    rx_map = mmap(NULL, rx_map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, xsk->fd, XDP_PGOFF_RX_RING);
    if (rx_map == MAP_FAILED) {
        perror("mmap RX ring");
        goto cleanup;
    }

    size_t fq_map_size = off.fr.desc + NUM_FRAMES * sizeof(__u64);
    fq_map = mmap(NULL, fq_map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, xsk->fd, XDP_UMEM_PGOFF_FILL_RING);
    if (fq_map == MAP_FAILED) {
        perror("mmap FQ ring");
        munmap(rx_map, rx_map_size);
        goto cleanup;
    }

    size_t cq_map_size = off.cr.desc + NUM_FRAMES * sizeof(__u64);
    cq_map = mmap(NULL, cq_map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, xsk->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (cq_map == MAP_FAILED) {
        perror("mmap CQ ring");
        munmap(rx_map, rx_map_size);
        munmap(fq_map, fq_map_size);
        goto cleanup;
    }

    // Initialize rings with correct offsets
    xdp_ring_init(&xsk->rx, rx_map, off.rx.producer, NUM_FRAMES);
    xdp_ring_init(&xsk->fq, fq_map, off.fr.producer, NUM_FRAMES);
    xdp_ring_init(&xsk->cq, cq_map, off.cr.producer, NUM_FRAMES);
    
    // Set descriptor pointers
    xsk->rx.desc = (struct xdp_desc*)((char*)rx_map + off.rx.desc);
    xsk->fq.desc = (void*)((char*)fq_map + off.fr.desc);
    xsk->cq.desc = (void*)((char*)cq_map + off.cr.desc);

    // Bind socket
    sxdp.sxdp_family = AF_XDP;
    sxdp.sxdp_ifindex = xsk->ifindex;
    sxdp.sxdp_queue_id = queue_id;
    sxdp.sxdp_flags = XDP_ZEROCOPY;  // Try zero-copy first

    ret = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
    if (ret) {
        // Fallback to copy mode
        sxdp.sxdp_flags = XDP_COPY;
        ret = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
        if (ret) {
            perror("bind");
            goto cleanup;
        }
        printf("AF_XDP: Using copy mode\n");
    } else {
        printf("AF_XDP: Using zero-copy mode\n");
    }

    // Fill the Fill Queue
    __u32 idx;
    for (int i = 0; i < NUM_FRAMES; i++) {
        idx = (*xsk->fq.producer + i) % NUM_FRAMES;
        *((__u64 *)xsk->fq.desc + idx) = i * FRAME_SIZE;
    }
    __sync_synchronize();
    *xsk->fq.producer += NUM_FRAMES;

    return 0;

cleanup:
    munmap(umem_area, xsk->umem.size);
    close(xsk->fd);
    return -1;
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

static void process_packets(struct afxdp_socket *xsk, FILE *output_file) {
    __u32 idx_rx, idx_fq;
    int rcvd;
    
    while (keep_running) {
        rcvd = 0;
        
        // Check available packets in RX ring
        __u32 entries = *xsk->rx.producer - *xsk->rx.consumer;
        if (entries == 0) {
            usleep(1000);  // 1ms sleep if no packets
            continue;
        }
        
        if (entries > BATCH_SIZE) {
            entries = BATCH_SIZE;
        }

        // Process received packets
        for (__u32 i = 0; i < entries; i++) {
            idx_rx = (*xsk->rx.consumer + i) % NUM_FRAMES;
            struct xdp_desc *desc = &((struct xdp_desc *)xsk->rx.desc)[idx_rx];
            
            void *pkt_data = (void *)((char *)xsk->umem.buffer + desc->addr);
            __u32 pkt_len = desc->len;
            
            // Write packet to PCAP file
            struct pcap_pkthdr pkt_hdr;
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            
            pkt_hdr.ts.tv_sec = ts.tv_sec;
            pkt_hdr.ts.tv_usec = ts.tv_nsec / 1000;
            pkt_hdr.caplen = pkt_len;
            pkt_hdr.len = pkt_len;
            
            fwrite(&pkt_hdr, sizeof(pkt_hdr), 1, output_file);
            fwrite(pkt_data, pkt_len, 1, output_file);
            
            packet_count++;
            rcvd++;
            
            // Return frame to Fill Queue
            idx_fq = (*xsk->fq.producer) % NUM_FRAMES;
            *((__u64 *)xsk->fq.desc + idx_fq) = desc->addr;
            (*xsk->fq.producer)++;
        }
        
        // Update consumer pointer
        *xsk->rx.consumer += rcvd;
        
        if (rcvd > 0) {
            fflush(output_file);
        }
    }
}

static void print_stats(int stats_fd) {
    __u64 rx_packets, captured, dropped, errors;
    __u32 key;
    
    key = 0; bpf_map_lookup_elem(stats_fd, &key, &rx_packets);
    key = 1; bpf_map_lookup_elem(stats_fd, &key, &captured);
    key = 2; bpf_map_lookup_elem(stats_fd, &key, &dropped);
    key = 3; bpf_map_lookup_elem(stats_fd, &key, &errors);
    
    printf("\rRX: %llu, Captured: %llu, Dropped: %llu, Errors: %llu, Saved: %d",
           rx_packets, captured, dropped, errors, packet_count);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <interface> <output.pcap>\n", argv[0]);
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
    struct bpf_object *obj;
    int prog_fd, xsks_map_fd;
    
    obj = bpf_object__open("xdp_afxdp.o");
    if (!obj) {
        fprintf(stderr, "Failed to open XDP object file\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load XDP program\n");
        bpf_object__close(obj);
        return 1;
    }
    
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "xdp_afxdp_redirect"));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(obj);
        return 1;
    }
    prog_fd_global = prog_fd;
    
    xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    
    // Create AF_XDP socket
    struct afxdp_socket xsk;
    if (create_af_xdp_socket(&xsk, ifname, 0) < 0) {
        fprintf(stderr, "Failed to create AF_XDP socket\n");
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
        bpf_object__close(obj);
        return 1;
    }
    
    // Attach XDP program
    if (bpf_xdp_attach(xsk.ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL)) {
        perror("bpf_xdp_attach");
        close(xsk.fd);
        bpf_object__close(obj);
        return 1;
    }
    
    printf("AF_XDP packet capture started on %s, saving to %s\n", ifname, output_filename);
    printf("Press Ctrl+C to stop\n");
    
    // Statistics printing thread simulation
    time_t last_stats = 0;
    
    while (keep_running) {
        process_packets(&xsk, output_file_ptr);
        
        time_t now = time(NULL);
        if (now - last_stats >= 1) {
            print_stats(stats_map_fd);
            last_stats = now;
        }
    }
    
    printf("\nShutting down...\n");
    
    close(xsk.fd);
    bpf_object__close(obj);
    
    return 0;
}