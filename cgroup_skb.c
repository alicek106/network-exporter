// +build ignore

#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})

// TODO: implement dequeue ip at main.go to prevent to be full of max_entries.
// 나중에 할 것
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} count_egress_packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} count_ingress_packets SEC(".maps");

#define EGRESS_DIRECTION 0
#define INGRESS_DIRECTION 1

int handle_packet(struct __sk_buff* skb, int direction) {
    __u64 bytes = 0;
    __u32 ip_val = 0;

    switch (skb->family)
    {
    case AF_INET:
        {
            struct iphdr iph;
            bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
            bytes = ntohs(iph.tot_len);

            if (direction == EGRESS_DIRECTION) {
                ip_val = iph.daddr;
                __u64 *bytes_counter = bpf_map_lookup_elem(&count_egress_packets, &iph.daddr);
                if (!bytes_counter) {
                    bpf_map_update_elem(&count_egress_packets, &ip_val, &bytes, BPF_NOEXIST);
                    return 1;
                }
                __sync_fetch_and_add(bytes_counter, bytes);
            } else if (direction == INGRESS_DIRECTION){
                ip_val = iph.saddr;
                __u64 *bytes_counter = bpf_map_lookup_elem(&count_ingress_packets, &iph.saddr);
                if (!bytes_counter) {
                    bpf_map_update_elem(&count_ingress_packets, &ip_val, &bytes, BPF_NOEXIST);
                    return 1;
                }
                __sync_fetch_and_add(bytes_counter, bytes);
            } else {
                // 정의되지 않음
                return 1;
            }

            return 1;
        }
    case AF_INET6:
        {
            // ipv6는 고려하지 않음
            return 1;
        }
    default:
        // This should never be the case as this eBPF hook is called in
        // netfilter context and thus not for AF_PACKET, AF_UNIX nor AF_NETLINK
        // for instance.
        return true;
    }

    return 1;
}


SEC("cgroup_skb/egress")
int count_egress_packets_func(struct __sk_buff *skb) {
    return handle_packet(skb, EGRESS_DIRECTION);
}

SEC("cgroup_skb/ingress")
int count_ingress_packets_func(struct __sk_buff *skb) {
    return handle_packet(skb, INGRESS_DIRECTION);
}

char __license[] SEC("license") = "Dual MIT/GPL";
