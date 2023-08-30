#include <linux/bpf.h>
//#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} packet_size_map SEC(".maps"); // 수정할 부분


static inline int bpf_memcmp(const void *s1, const void *s2, unsigned int n) {
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;

    for (unsigned int i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            return (p1[i] < p2[i]) ? -1 : 1;
        }
    }

    return 0;
}

SEC("prog")
int drop_all(struct __sk_buff *skb) {
    __u32 size_key = 0; // Since max_entries is 1, we'll just use 0 as the key
    __u32 offset_key = 1; // Since max_entries is 1, we'll just use 0 as the key
   __u64 packet_size = skb->len;

    char delimiter[2];
    char redis_cmd[3];
    struct tcphdr tcp_header;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &tcp_header, sizeof(tcp_header)) != 0)
        return -1; // Drop packet
   

    //__u32 tcp_hdr_len = tcp_header.doff*4;
    __u32 tcp_hdr_len = tcp_header.doff*2;

    if(bpf_skb_load_bytes(skb, ETH_HLEN+sizeof(struct iphdr)+tcp_hdr_len, &redis_cmd,sizeof(redis_cmd)) !=0 )
         return -1;

    if(bpf_memcmp(redis_cmd,"set",3)!=0 && bpf_memcmp(redis_cmd,"SET",3)!=0)
         return -1;

    __u64 offset = ETH_HLEN+sizeof(struct iphdr)+tcp_hdr_len+3; // set(3) \r\n(2) $3\r\n(4) key\r\n(5)
     
     /* Now we need to find the next \r\n */
     


    for (int j = 0; j < 4; ++j){
        for(int i=0; i<512; ++i){ // Assuming a maximum of 512 bytes to search
            if(bpf_skb_load_bytes(skb,offset+i, &delimiter,sizeof(delimiter))!=0)
              continue;
          if(bpf_memcmp(delimiter,"\r\n",2)==0){
              /* Found the next \r\n. The value starts after this */
              offset += i+2;
              break;
            }
        }
    }
    packet_size -= offset + 2; // 2(\r\n)
    offset -= (ETH_HLEN+sizeof(struct iphdr)-2);
    bpf_map_update_elem(&packet_size_map, &size_key, &packet_size, BPF_ANY);
    bpf_map_update_elem(&packet_size_map, &offset_key, &offset, BPF_ANY);
    return -1;

}


char _license[] SEC("license") = "GPL";
