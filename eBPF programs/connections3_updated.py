#!/usr/bin/python
from bcc import BPF
from ctypes import c_int
from time import sleep

# BPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <libbpf/include/uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
//#include <linux/filter.h>
#include <linux/socket.h>
//BPF_HASH(conn_count, u64, char[40]);

int count_connection(struct __sk_buff *skb) {
    void *data = (void *)(long)(skb->data);
    bpf_trace_printk("Check 1");
    void * data_end = (void *)(long)(skb->data_end);
    bpf_trace_printk("Check 2");
    if(data==NULL){
        bpf_trace_printk("Data=null");
        return 0;
    }
    if(data_end==NULL){
        bpf_trace_printk("Data end =null");
        return 0;
    }
    if (data > data_end) {
        bpf_trace_printk("Data out of bounds");
        return 0;  // Drop the packet if out of bounds
    }
    bpf_trace_printk("Check 3");
    u64 pid = bpf_get_current_pid_tgid();
    //int *count = conn_count.lookup(&pid);
    //if (!count) {
        //int initial_count = 1;
        //conn_count.update(&pid, &initial_count);
    //} else {
        //(*count)++;
    //}
    bpf_trace_printk("Hello World");

    return 0;
}
"""

# Initialize BPF
b = BPF(text=prog)

# Attach the BPF program to trace TCP connect events
b.attach_kprobe(event="tcp_recvmsg", fn_name="count_connection")
#b.attach_kprobe(event="tcp_v4_connect", fn_name="count_connection")

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

b.trace_print()
