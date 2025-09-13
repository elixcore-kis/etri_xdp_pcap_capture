#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 1024

// AF_XDP socket map for redirecting packets
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);  // Support up to 64 queues
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Statistics map
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
int xdp_afxdp_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    update_stat(STAT_RX_PACKETS);
    
    // Basic packet validation
    if (data + sizeof(struct ethhdr) > data_end) {
        update_stat(STAT_ERRORS);
        return XDP_PASS;
    }
    
    // Get the queue index for AF_XDP redirect
    __u32 queue_id = ctx->rx_queue_index;
    
    // Try to redirect to AF_XDP socket
    if (bpf_map_lookup_elem(&xsks_map, &queue_id)) {
        update_stat(STAT_CAPTURED);
        return bpf_redirect_map(&xsks_map, queue_id, 0);
    }
    
    // If no AF_XDP socket found, pass to network stack
    update_stat(STAT_DROPPED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";