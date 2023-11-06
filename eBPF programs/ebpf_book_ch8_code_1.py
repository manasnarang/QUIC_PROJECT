from bcc import BPF
# BPF program code
bpf_program = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
// SEC(“xdp”);
int ping(struct __sk_buff *ctx) {
    struct ethhdr *eth = bpf_hdr_pointer(0);
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (ip->protocol == IPPROTO_ICMP) {
        bpf_printk(“Hello ping\n”);
    }
    return XDP_PASS;
}
"""
# Load BPF program
b = BPF(text=bpf_program)
# Attach the program to an interface (e.g., “eth0”)
b.attach_xdp(device="eth0", program=b.get_function("ping"))
try:
    b.trace_print()
except KeyboardInterrupt:
    pass
# Detach the XDP program
b.remove_xdp(device="eth0")