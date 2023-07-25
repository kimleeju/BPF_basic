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
    __uint(max_entries, 1024);
} packet_size_map SEC(".maps"); // 수정할 부분

SEC("prog")
int drop_all(struct __sk_buff *skb) {
    __u32 key = 0; // Since max_entries is 1, we'll just use 0 as the key
    __u64 packet_size = skb->len; // Get current packet size
    
    // Update the BPF map with the current packet size
    bpf_map_update_elem(&packet_size_map, &key, &packet_size, BPF_ANY);
//    return 0;
    return -1;
}

char _license[] SEC("license") = "GPL";
