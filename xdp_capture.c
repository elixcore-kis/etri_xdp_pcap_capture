#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PACKET_SIZE 1500  // Standard Ethernet MTU
#define MAX_ENTRIES 1024

struct packet_info {
    __u64 timestamp;
    __u32 len;
    __u32 caplen;
    __u8 data[MAX_PACKET_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_ENTRIES * sizeof(struct packet_info));
} packet_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_RX_PACKETS     0
#define STAT_CAPTURED       1
#define STAT_DROPPED        2
#define STAT_ERRORS         3

static void update_stat(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

SEC("xdp")
int xdp_packet_capture(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u32 pkt_len = data_end - data;
    
    update_stat(STAT_RX_PACKETS);
    
    // Basic packet validation
    if (data + sizeof(struct ethhdr) > data_end) {
        update_stat(STAT_ERRORS);
        return XDP_PASS;
    }
    
    // Limit packet size for ringbuf
    __u32 copy_len = pkt_len > MAX_PACKET_SIZE ? MAX_PACKET_SIZE : pkt_len;
    
    // Reserve space in ringbuf
    struct packet_info *pkt_info = bpf_ringbuf_reserve(&packet_ringbuf, 
                                                       sizeof(struct packet_info), 0);
    if (!pkt_info) {
        update_stat(STAT_DROPPED);
        return XDP_PASS;
    }
    
    // Fill packet info
    pkt_info->timestamp = bpf_ktime_get_ns();
    pkt_info->len = pkt_len;
    pkt_info->caplen = copy_len;
    
    // Limit copy length to available data and max size
    if (copy_len > MAX_PACKET_SIZE) {
        copy_len = MAX_PACKET_SIZE;
    }
    
    if (data + copy_len > data_end) {
        copy_len = data_end - data;
    }
    
    pkt_info->caplen = copy_len;
    
    // Direct memory copy with bounds checking for each byte
    // Unrolled loop for first 64 bytes to satisfy BPF verifier
    __u8 *src = (__u8*)data;
    __u8 *dst = pkt_info->data;
    
    for (__u32 i = 0; i < MAX_PACKET_SIZE && i < copy_len; i++) {
        if (src + i + 1 > (__u8*)data_end) break;
        dst[i] = src[i];
    }
    
    // Submit to userspace
    bpf_ringbuf_submit(pkt_info, 0);
    update_stat(STAT_CAPTURED);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";