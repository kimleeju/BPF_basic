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
    __uint(max_entries, 3);
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
    __u32 size = 0; // Since max_entries is 1, we'll just use 0 as the key
    __u32 value_offset = 1; // Since max_entries is 1, we'll just use 0 as the key
   __u64 packet_size = skb->len;

    char delimiter[2];
    char redis_cmd[3];
    struct tcphdr tcp_header;
    __u64 offset = 1;

    if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &tcp_header, sizeof(tcp_header)) != 0){
//        packet_size = 0;
//        bpf_map_update_elem(&packet_size_map, &size, &packet_size, BPF_ANY);
        return -1;
    }
   
    //__u32 tcp_hdr_len = tcp_header.doff*4;
    __u32 tcp_hdr_len = tcp_header.doff*2;

    if(bpf_skb_load_bytes(skb, ETH_HLEN+sizeof(struct iphdr)+tcp_hdr_len, &redis_cmd,sizeof(redis_cmd)) !=0 ){
        return -1;
    }

    if(bpf_memcmp(redis_cmd,"set",3)!=0 && bpf_memcmp(redis_cmd,"SET",3)!=0){
        if(bpf_memcmp(redis_cmd,"xxx",3)==0 || bpf_memcmp(redis_cmd,"XXX",3)==0)
            return -1;

        packet_size = 0;
        bpf_map_update_elem(&packet_size_map, &size, &packet_size, BPF_ANY);
#if 1
        if(bpf_memcmp(redis_cmd,"",1)==0){
            offset = 0;
            bpf_map_update_elem(&packet_size_map, &value_offset, &offset, BPF_ANY);
        }
#endif
        return -1;
    }
    offset = ETH_HLEN+sizeof(struct iphdr)+tcp_hdr_len+3; // set(3) \r\n(2) $3\r\n(4) key\r\n(5)
     
     /* Now we need to find the next \r\n */
    char value_size[10];
    int val_ptr;
    for (int j = 0; j < 4; ++j){
        for(int i=0; i<512; ++i){ // Assuming a maximum of 512 bytes to search
            if(bpf_skb_load_bytes(skb,offset+i, &delimiter,sizeof(delimiter))!=0)
              continue;
          if(bpf_memcmp(delimiter,"\r\n",2)==0){
              offset += i+2;
              if (j == 2){
                val_ptr = offset+1; //$제거 
             }
              break;
            }
        }
    }
    
    bpf_skb_load_bytes(skb,val_ptr, &value_size,sizeof(value_size));
//    bpf_printk("%s\n",value_size); 
    packet_size -= offset + 2; // 2(\r\n)
    offset -= (ETH_HLEN+sizeof(struct iphdr)-2);
    bpf_map_update_elem(&packet_size_map, &size, &value_size, BPF_ANY);
    //bpf_map_update_elem(&packet_size_map, &size, &packet_size, BPF_ANY);
    bpf_map_update_elem(&packet_size_map, &value_offset, &offset, BPF_ANY);
    return -1;

}


char _license[] SEC("license") = "GPL";
