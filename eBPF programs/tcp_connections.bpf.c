//# include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/filter.h>
#include <linux/socket.h>

struct data_t { 
    __be32 source_ip_addr;
    __be32 dest_ip_addr;
    __be16 source_port;
    __be16 dest_port;
};

BPF_MAP_DEF(tcp_connection_map) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct data_t),
    .value_size = sizeof(int),
    .max_entries = 10000,
};

BPF_MAP_ADD(tcp_connection_map);

int info_connection(struct __sk_buff *skb) {
    void *data = (void *)(long)(skb->data);
    void * data_end = (void *)(long)(skb->data_end);
    if (data > data_end) {
        return TC_ACT_SHOT;  // Drop the packet if out of bounds
    }
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_SHOT;  // Drop the packet if out of bounds
    }
    struct iphdr *ip = data + sizeof(struct ethhdr); // Pointer to the IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_SHOT; // Drop the packet if out of bounds
    }
    if (ip->protocol == IPPROTO_TCP) {
        return TC_ACT_SHOT;
    }
    struct tcphdr * tcp_st1 = data + sizeof(struct ethhdr)+(ip->ihl << 2);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_SHOT; // Drop the packet if out of bounds
    }
    struct data_t * data1;
    data1->source_ip_addr=ip->saddr;
    data1->dest_ip_addr=ip->daddr;
    data1->source_port=tcp_st1->source;
    data1->dest_port=tcp_st1->dest;
    int * count=bpf_map_lookup_elem(&tcp_connection_map, &data1);
    int number=0;
    if(count!=0){
        number=*p;
    }
    number=number+1
    bpf_map_update_elem(&tcp_connection_map, &data1, &number);
    return TC_ACT_OK;
}
