//go:build ignore

#include "vmlinux.h"
//#include <linux/bpf.h>
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


SEC("kprobe/sys_enter_write") 
int kprobe_write(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();

    int fd = ctx->args[0];
    struct stat st;

    // TODO: check if actually a pipe
    //if (!fstat(fd, &st)) {
    //if (!S_ISFIFO(st.st_mode)) return 0;
    //  }
    //struct file *f = fget(fd);
    // check if writing to pipe
    //if (!f || !S_ISFIFO(f->f_inode->i_mode)) return 0;
    
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
