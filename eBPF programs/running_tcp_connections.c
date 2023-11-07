#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bcc/libbpf.h>

int main() {
    struct bpf_object *obj;
    int map_fd;
    int prog_fd;
    int ret;

    // Load the eBPF program
    ret = bpf_prog_load("tcp_connect.c", BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
    if (ret) {
        fprintf(stderr, "Error loading BPF program: %s\n", strerror(ret));
        return 1;
    }

    // Load the BPF map
    map_fd = bpf_object__find_map_fd_by_name(obj, "conn_counts");
    if (map_fd < 0) {
        fprintf(stderr, "Error finding BPF map: %s\n", strerror(map_fd));
        return 1;
    }

    // Attach the eBPF program to the tcp_v4_connect tracepoint
    ret = bpf_attach_tracepoint(obj, prog_fd, "tcp", "tcp_v4_connect", -1);
    if (ret) {
        fprintf(stderr, "Error attaching BPF program to tracepoint: %s\n", strerror(ret));
        return 1;
    }

    printf("eBPF program attached. Press Ctrl+C to stop.\n");

    // Wait for Ctrl+C to exit
    while (1) {
        sleep(1);
    }

    return 0;
}
