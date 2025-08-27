//go:build ignore

#include "vmlinux.h"
//#include <linux/bpf.h>
//#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
    u32 pid;
    int fd;
    //u64 bytes;
    u64 ts;
    char comm[16];
    //char type; // 'R' vs 'W'
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); 
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} writes SEC(".maps"); 


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, u32); // key: pid
    __type(value, int);
} pipe_writers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, u32); // key: pid
    __type(value, int);
} pipe_readers SEC(".maps");

SEC("kprobe/sys_enter_write") 
int kprobe_write(struct trace_event_raw_sys_enter *ctx) {
    //bpf_printk("write!");
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    
    //check if pid in pipe_writers
    if (!bpf_map_lookup_elem(&pipe_writers, &pid)) {
         return 0;
    }
    //pid >>= 32;

    int fd = ctx->args[0];
    struct stat st;
    
    e = bpf_ringbuf_reserve(&writes, sizeof(struct event), 0);
    if (!e) {
    	return 0;
    }

    e->pid = pid;
    e->ts = ts;
    e->fd = fd;

    bpf_get_current_comm(&e->comm, 16);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("kprobe/sys_enter_dup2")
int kprobe_dup2(struct trace_event_raw_sys_enter *ctx) {
     bpf_printk("got here");
     u32 pid = bpf_get_current_pid_tgid();
     //pid >>= 32;

     //int old_fd = PT_REGS_PARM1_CORE(ctx);
     //int new_fd = PT_REGS_PARM2_CORE(ctx);
     int oldfd = ctx->args[0];   
     int newfd = ctx->args[1];
     bpf_printk("old: %d, new: %d", oldfd, newfd);
     int test = 1;

     if (newfd == 0) { // mapping to stdin: add pid to pipe_readers
        bpf_printk("stdin!");
	bpf_map_update_elem(&pipe_readers, &pid, &test, BPF_ANY);
     } else if (newfd == 1) { // mapping to stdout: add pid to pipe_writers
        bpf_printk("[DUP2] [%d] Setting stdout to fd %d\n", pid, oldfd);
	bpf_map_update_elem(&pipe_writers, &pid, &test, BPF_ANY);
     }
     return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
