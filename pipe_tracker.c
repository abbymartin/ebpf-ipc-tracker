//go:build ignore

#include "vmlinux.h"
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
    u32 pid;
    //int fd;
    //u64 bytes;
    u64 ts;
    char comm[16];
    //char type; // 'R' vs 'W'
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); 
    __uint(max_entries, 1 << 24);
    //__type(value, struct event);
} writes SEC(".maps"); 


SEC("kprobe/sys_write") 
int kprobe_write(struct pt_regs *ctx) {
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    
    e = bpf_ringbuf_reserve(&writes, sizeof(struct event), 0);
    if (!e) {
    	return 0;
    }

    e->pid = pid;
    e->ts = ts;

    bpf_get_current_comm(&e->comm, 16);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
