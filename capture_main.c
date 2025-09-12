#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_link.h>
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

#define MAX_PACKET_SIZE 512  // Match XDP program

struct packet_info {
    __u64 timestamp;
    __u32 len;
    __u32 caplen;
    __u8 data[MAX_PACKET_SIZE];
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
    printf("\nReceived signal, cleaning up...\n");
    
    if (src_ifindex_global > 0) {
        bpf_xdp_detach(src_ifindex_global, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        printf("XDP program detached from interface\n");
    }
    
    if (prog_fd_global >= 0) {
        close(prog_fd_global);
    }
    
    if (output_file_ptr) {
        fclose(output_file_ptr);
    }
    
    printf("Total packets captured: %d\n", packet_count);
}

static int get_ifindex(const char *ifname) {
    return if_nametoindex(ifname);
}

static void print_stats(void) {
    __u64 rx_packets = 0, captured = 0, dropped = 0, errors = 0;
    __u32 key;
    
    if (stats_map_fd < 0) return;
    
    key = 0; bpf_map_lookup_elem(stats_map_fd, &key, &rx_packets);
    key = 1; bpf_map_lookup_elem(stats_map_fd, &key, &captured);
    key = 2; bpf_map_lookup_elem(stats_map_fd, &key, &dropped);
    key = 3; bpf_map_lookup_elem(stats_map_fd, &key, &errors);
    
    printf("\n=== XDP Capture Statistics ===\n");
    printf("RX Packets:       %llu\n", rx_packets);
    printf("Captured:         %llu\n", captured);
    printf("Dropped:          %llu\n", dropped);
    printf("Errors:           %llu\n", errors);
    printf("==============================\n");
}

static int write_pcap_header(FILE *fp) {
    struct pcap_file_header hdr;
    
    hdr.magic = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = MAX_PACKET_SIZE;
    hdr.linktype = 1; // DLT_EN10MB (Ethernet)
    
    return fwrite(&hdr, sizeof(hdr), 1, fp) == 1 ? 0 : -1;
}

static int write_packet_to_pcap(FILE *fp, const struct packet_info *pkt) {
    struct pcap_pkthdr pcap_hdr;
    
    // Convert nanoseconds to seconds and microseconds
    pcap_hdr.ts.tv_sec = pkt->timestamp / 1000000000ULL;
    pcap_hdr.ts.tv_usec = (pkt->timestamp % 1000000000ULL) / 1000;
    pcap_hdr.caplen = pkt->caplen;
    pcap_hdr.len = pkt->len;
    
    if (fwrite(&pcap_hdr, sizeof(pcap_hdr), 1, fp) != 1) {
        return -1;
    }
    
    if (fwrite(pkt->data, pkt->caplen, 1, fp) != 1) {
        return -1;
    }
    
    return 0;
}

static int packet_callback(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    
    if (data_sz < sizeof(struct packet_info)) {
        fprintf(stderr, "Invalid packet data size\n");
        return 0;
    }
    
    struct packet_info *pkt = (struct packet_info *)data;
    
    if (write_packet_to_pcap(output_file_ptr, pkt) < 0) {
        fprintf(stderr, "Failed to write packet to pcap file\n");
        return -1;
    }
    
    packet_count++;
    
    if (packet_count % 100 == 0) {
        printf("Captured %d packets...\n", packet_count);
        fflush(output_file_ptr);
    }
    
    return 0;
}

static struct bpf_object *global_obj = NULL;

static int setup_xdp_program(const char *ifname, const char *output_file) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *stats_map;
    int ifindex;
    __u64 zero = 0;
    
    ifindex = get_ifindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error: interface %s not found\n", ifname);
        return -1;
    }
    src_ifindex_global = ifindex;
    
    // Load BPF program
    obj = bpf_object__open_file("xdp_capture.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file\n");
        return -1;
    }
    
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "Error loading BPF object\n");
        bpf_object__close(obj);
        return -1;
    }
    
    prog = bpf_object__find_program_by_name(obj, "xdp_packet_capture");
    if (!prog) {
        fprintf(stderr, "Error finding BPF program\n");
        bpf_object__close(obj);
        return -1;
    }
    
    prog_fd_global = bpf_program__fd(prog);
    if (prog_fd_global < 0) {
        fprintf(stderr, "Error getting program FD\n");
        bpf_object__close(obj);
        return -1;
    }
    
    // Get stats map
    stats_map = bpf_object__find_map_by_name(obj, "stats");
    if (stats_map) {
        stats_map_fd = bpf_map__fd(stats_map);
        
        // Initialize stats to zero
        for (int i = 0; i < 4; i++) {
            __u32 key = i;
            bpf_map_update_elem(stats_map_fd, &key, &zero, BPF_ANY);
        }
    }
    
    // Open pcap file
    output_file_ptr = fopen(output_file, "wb");
    if (!output_file_ptr) {
        fprintf(stderr, "Error opening output file %s: %s\n", output_file, strerror(errno));
        bpf_object__close(obj);
        return -1;
    }
    
    if (write_pcap_header(output_file_ptr) < 0) {
        fprintf(stderr, "Error writing pcap header\n");
        fclose(output_file_ptr);
        bpf_object__close(obj);
        return -1;
    }
    
    // Attach XDP program
    if (bpf_xdp_attach(ifindex, prog_fd_global, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL) != 0) {
        fprintf(stderr, "Error attaching XDP program to %s\n", ifname);
        fclose(output_file_ptr);
        bpf_object__close(obj);
        return -1;
    }
    
    printf("XDP packet capture program loaded successfully!\n");
    printf("Interface: %s\n", ifname);
    printf("Output file: %s\n", output_file);
    
    // Store global reference to BPF object
    global_obj = obj;
    
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <output_file.pcap>\n", argv[0]);
        fprintf(stderr, "Example: %s ens20 capture.pcap\n", argv[0]);
        return 1;
    }
    
    const char *ifname = argv[1];
    const char *output_file = argv[2];
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (setup_xdp_program(ifname, output_file) != 0) {
        fprintf(stderr, "Failed to setup XDP program\n");
        return 1;
    }
    
    // Use the same BPF object instance
    if (!global_obj) {
        fprintf(stderr, "Error: BPF object not initialized\n");
        return 1;
    }
    
    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(global_obj, "packet_ringbuf");
    if (!ringbuf_map) {
        fprintf(stderr, "Error finding ringbuf map\n");
        return 1;
    }
    
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(ringbuf_map), packet_callback, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Error creating ring buffer\n");
        return 1;
    }
    
    printf("Press Ctrl+C to stop capture\n\n");
    
    time_t start_time = time(NULL);
    int counter = 0;
    
    while (keep_running) {
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0 && ret != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", ret);
            break;
        }
        
        counter++;
        if (counter % 50 == 0) {  // Print stats every 5 seconds
            print_stats();
        }
    }
    
    time_t end_time = time(NULL);
    double duration = difftime(end_time, start_time);
    
    printf("\n=== Final Capture Summary ===\n");
    printf("Total packets captured: %d\n", packet_count);
    printf("Capture duration: %.0f seconds\n", duration);
    if (duration > 0) {
        printf("Average rate: %.2f packets/second\n", packet_count / duration);
    }
    printf("Output file: %s\n", output_file);
    
    print_stats();
    
    ring_buffer__free(rb);
    if (global_obj) {
        bpf_object__close(global_obj);
    }
    
    return 0;
}