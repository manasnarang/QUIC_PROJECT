from bcc import BPF

# eBPF program
ebpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>

int trace_tcp_congestion(struct pt_regs *ctx, struct sock *sk) {
    struct tcp_sock *tsk;
    u32 cwnd;

    // Cast sock to tcp_sock
    tsk = (struct tcp_sock *)sk;
    
    // Read congestion window
    cwnd = tsk->rcv_wnd;
    
    // Print congestion window
    bpf_trace_printk("Congestion Window: %u\\n", cwnd);

    return 0;
}
"""

# Create an eBPF module
b = BPF(text=ebpf_code)

# Attach the program to a Kprobe on the tcp_sendmsg function
b.attach_kprobe(event="tcp_ack", fn_name="trace_tcp_congestion")

# b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_congestion")
# b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_congestion")


# Print trace output
print("Tracing TCP congestion window...")

# Start tracing
try:
    b.trace_print()
except KeyboardInterrupt:
    pass
