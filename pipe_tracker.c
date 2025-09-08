//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define AF_UNIX 1

struct event {
    u32 pid;
    //int fd;
    //u64 bytes;
    u64 ts;
    char comm[16];
    char type; // 'R' vs 'W'
};

// ringbuf holding all pipe reads and writes
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); 
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} pipe_events SEC(".maps");

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

// map to keep track of fds we know are pipes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, int); // key: fd
    __type(value, u32); 
} pipe_fds SEC(".maps");

// TODO: change to tracepoints where possible (more efficient than kprobes)
// ^ current kernel bug w perf may be causing issues https://bugs.launchpad.net/ubuntu/+source/linux-hwe-6.14/+bug/2117159

SEC("fexit/do_pipe2")
int BPF_PROG(pipe2, int *filedes, int ret) {
    if (ret != 0)
        return 0;

    u32 pid = bpf_get_current_pid_tgid();

    int fds[2];

    bpf_probe_read_user(&fds, sizeof(fds), filedes);
    bpf_printk("fd0: %d, fd1: %d", fds[0], fds[1]);

    bpf_map_update_elem(&pipe_fds, &fds[0], &pid, BPF_ANY);
    bpf_map_update_elem(&pipe_fds, &fds[1], &pid, BPF_ANY);

    return 0;
}

// pipe setup uses dup2 syscall to map stdout or stdin to pipe fds (makes possible to exec w pipe)
SEC("kprobe/sys_enter_dup2")
int BPF_KPROBE(kprobe_dup2, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    int oldfd = PT_REGS_PARM1_CORE(regs);
    int newfd = PT_REGS_PARM2_CORE(regs);
    //bpf_printk("old: %d, new: %d", oldfd, newfd);

    if (oldfd == 0 || oldfd == 1) {
	    bpf_map_delete_elem(&pipe_readers, &pid);
	    bpf_map_delete_elem(&pipe_writers, &pid);
    }

    // make sure we are mapping a pipe fd
    if(!bpf_map_lookup_elem(&pipe_fds, &oldfd)) {
        return 0;
    }

    bpf_map_delete_elem(&pipe_fds, &oldfd);

    if (newfd == 0) { // mapping to stdin: add pid to pipe_readers
        bpf_printk("adding reader %d", oldfd);
	    bpf_map_update_elem(&pipe_readers, &pid, &newfd, BPF_ANY);
    } else if (newfd == 1) { // mapping to stdout: add pid to pipe_writers
        bpf_printk("adding writer %d", oldfd);
	    bpf_map_update_elem(&pipe_writers, &pid, &newfd, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/sys_enter_read")
int BPF_KPROBE(kprobe_read, struct pt_regs *regs) {
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();

    int fd = PT_REGS_PARM2_CORE(regs);

    // check if pid is in pipe_readers
    if (!bpf_map_lookup_elem(&pipe_writers, &pid)) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&pipe_events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->ts = ts;
    e->type = 'R';

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("kprobe/sys_enter_write")
int BPF_KPROBE(kprobe_write, struct pt_regs *regs) {
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    
    // check if pid is in pipe_writers
    if (!bpf_map_lookup_elem(&pipe_writers, &pid)) {
        return 0;
    }

    //int fd = PT_REGS_PARM1_CORE(regs);
    
    e = bpf_ringbuf_reserve(&pipe_events, sizeof(struct event), 0);
    if (!e) {
    	return 0;
    }

    e->pid = pid;
    e->ts = ts;
    e->type = 'W';
    //e->fd = fd;
    //bpf_get_current_comm(&e->comm, 16);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// remove from pipe reader/writer maps upon fd close or process exit
SEC("kprobe/sys_enter_close")
int BPF_KPROBE(kprobe_close, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    int fd = PT_REGS_PARM1_CORE(regs);

    int *reader_fd = bpf_map_lookup_elem(&pipe_readers, &pid);
    int *writer_fd = bpf_map_lookup_elem(&pipe_writers, &pid);

    // check if closing a pipe reader/writer
    if (!(reader_fd && *reader_fd == fd) || (writer_fd && *writer_fd == fd)) {
        return 0;
    }

    if (reader_fd) {
        int s = bpf_map_delete_elem(&pipe_readers, &pid);
        if (s == 0) {
            bpf_printk("close: delete reader %d, fd: %d", pid, *reader_fd);
        }
    } else if (writer_fd) {
        int s = bpf_map_delete_elem(&pipe_writers, &pid);
        if (s == 0) {
            bpf_printk("close: delete writer %d, fd: %d", pid, *writer_fd);
        }
    }

    return 0;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(kprobe_exit, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    int s = bpf_map_delete_elem(&pipe_readers, &pid);
    if (s == 0) {
       bpf_printk("exit: delete reader %d", pid);
    }
    
    s = bpf_map_delete_elem(&pipe_writers, &pid);
    if (s == 0) {
       bpf_printk("exit: delete writer %d", pid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
