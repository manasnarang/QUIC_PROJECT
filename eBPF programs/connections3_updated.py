#!/usr/bin/python
from bcc import BPF
from ctypes import c_int
from time import sleep

# BPF program
prog = """
#include <uapi/linux/ptrace.h>
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

// struct BPF_MAP_DEF {
//   unsigned int type;
//   unsigned int key_size;
//   unsigned int value_size;
//   unsigned int max_entries;
// };

BPF_HASH(tcp_connection_map,struct data_t,int);

int info_connection(struct __sk_buff *skb) {
    void *data = (void *)(long)(skb->data);
    void * data_end = (void *)(long)(skb->data_end);
    if (data > data_end) {
        return 0;  // Drop the packet if out of bounds
    }
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return 0;  // Drop the packet if out of bounds
    }
    struct iphdr *ip = data + sizeof(struct ethhdr); // Pointer to the IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return 0; // Drop the packet if out of bounds
    }
    if (ip->protocol == IPPROTO_TCP) {
        return 0;
    }
    struct tcphdr * tcp_st1 = data + sizeof(struct ethhdr)+(ip->ihl << 2);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return 0; // Drop the packet if out of bounds
    }
    struct data_t * data1;
    data1->source_ip_addr=ip->saddr;
    data1->dest_ip_addr=ip->daddr;
    data1->source_port=tcp_st1->source;
    data1->dest_port=tcp_st1->dest;
    int count=tcp_connection_map.lookup(&data1);
    int number=0;
    if(count!=0){
        number=*count;
    }
    number=number+1
    tcp_connection_map.update(&data1,&number);
    return 0;
}
"""

# Initialize BPF
b = BPF(text=prog)

# Attach the BPF program to trace TCP connect events
b.attach_kprobe(event="tcp_v4_connect", fn_name="info_connection")
b.attach_kprobe(event="tcp_v6_connect", fn_name="info_connection")

# # Dictionary to store connection counts per PID
# connection_count = {}

# # Read and display connection counts
# try:
#     while True:
#         sleep(3)
#         for (k, v) in b["conn_count"].items():
#             connection_count[k.value] = c_int(v.value).value
#         for pid, count in connection_count.items():
#             print("PID {}: {} TCP connections".format(pid, count))
# except KeyboardInterrupt:
#     pass
