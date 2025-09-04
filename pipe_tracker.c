//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//TODO: make header for perf event types? (if I go down the tracepoint route)

struct tp_hdr {
    u16 common_type;
    u8  common_flags;
    u8  common_preempt_count;
    s32 common_pid;
};

struct sys_enter_read_ctx {
    unsigned long padding;

    int __syscall_nr;
    unsigned int fd;
    char *buf;
    size_t count;
};

struct event {
    u32 pid;
    //int fd;
    //u64 bytes;
    u64 ts;
    char comm[16];
    char type; // 'R' vs 'W'
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); 
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} pipe_writes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} pipe_reads SEC(".maps");

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

SEC("tp/syscalls/sys_enter_read")
int trace_read(struct sys_enter_read_ctx *ctx) {
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();

    // check if pid is in pipe_readers
    if (!bpf_map_lookup_elem(&pipe_readers, &pid)) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&pipe_reads, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->ts = ts;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int trace_write(void *regs) {
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    
    // check if pid is in pipe_writers
    if (!bpf_map_lookup_elem(&pipe_writers, &pid)) {
         return 0;
    }

    //int fd = PT_REGS_PARM1_CORE(regs);
    
    e = bpf_ringbuf_reserve(&pipe_writes, sizeof(struct event), 0);
    if (!e) {
    	return 0;
    }

    e->pid = pid;
    e->ts = ts;
    //e->fd = fd;
    //bpf_get_current_comm(&e->comm, 16);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// pipe setup uses dup2 syscall to map stdout or stdin to pipe fds (makes possible to exec w pipe)
// track dup2 that use stdout or stdin and add to pipe_readers or pipe_writers
SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct pt_regs *regs) {
     u32 pid = bpf_get_current_pid_tgid();

     int oldfd = PT_REGS_PARM1_CORE(regs);
     int newfd = PT_REGS_PARM2_CORE(regs);
     //bpf_printk("old: %d, new: %d", oldfd, newfd);

     if (oldfd == 0 || oldfd == 1) {
	bpf_map_delete_elem(&pipe_readers, &pid);
	bpf_map_delete_elem(&pipe_writers, &pid);
     }

     if (newfd == 0) { // mapping to stdin: add pid to pipe_readers
        bpf_printk("add reader: %d", pid);
	bpf_map_update_elem(&pipe_readers, &pid, &pid, BPF_ANY);
     } else if (newfd == 1) { // mapping to stdout: add pid to pipe_writers
	bpf_printk("add writer: %d", pid);
	bpf_map_update_elem(&pipe_writers, &pid, &pid, BPF_ANY);
     }

     return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    int fd = PT_REGS_PARM1_CORE(regs);
    //bpf_printk("close file: %d for pid: %d", fd, pid);

    if (fd == 0) {    
        int s = bpf_map_delete_elem(&pipe_readers, &pid);
	bpf_printk("close: delete reader %d, result: %d", pid, s);
	return 0;
    } else if (fd == 1) {
        int s = bpf_map_delete_elem(&pipe_writers, &pid);
	bpf_printk("close: delete writer %d, result: %d", pid, s);
    }

    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe_exit, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    int s = bpf_map_delete_elem(&pipe_readers, &pid);
    bpf_printk("exit: delete reader %d, result: %d", pid, s);
    s = bpf_map_delete_elem(&pipe_writers, &pid);
    bpf_printk("exit: delete writer %d, result: %d", pid, s);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
