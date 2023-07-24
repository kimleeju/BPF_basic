#include <linux/bpf.h>
//#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAP_NAME "packet_count_map"
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} packet_size_map SEC(".maps"); // 수정할 부분

SEC("prog")
int drop_all(struct __sk_buff *skb) {
#if 0
    __u32 key = bpf_htonl(INADDR_ANY);
    __u64 *value;
    
    value = bpf_map_lookup_elem(&packet_count_map, &key); // 수정할 부분
    if (value)
        __sync_fetch_and_add(value, skb->len); 
    else {
        __u64 init_val = skb->len;
        bpf_map_update_elem(&packet_count_map, &key, &init_val, BPF_ANY); // 수정할 부분
    }
    
    return 1; // Drop all packets.
#endif

    __u32 key = 0; // Since max_entries is 1, we'll just use 0 as the key
    __u64 packet_size = skb->len; // Get current packet size
    
    // Update the BPF map with the current packet size
    bpf_map_update_elem(&packet_size_map, &key, &packet_size, BPF_ANY);

    return 1; // Drop all packets.
}

char _license[] SEC("license") = "GPL";
