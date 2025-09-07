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


// TODO: look into: process can map own read AND write (why?)
// will pipe always call dup2? also what else can result in dup2 on stdin/stdout instead of pipe?
// testing: adding a lot more writers than readers, shouldn't write end need a read end?
SEC("kprobe/sys_enter_read")
int BPF_KPROBE(kprobe_read, struct pt_regs *regs) {
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();

    // check if pid is in pipe_readers
    if (!bpf_map_lookup_elem(&pipe_readers, &pid)) {
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

// pipe setup uses dup2 syscall to map stdout or stdin to pipe fds (makes possible to exec w pipe)
// track dup2 that use stdout or stdin and add to pipe_readers or pipe_writers
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

    if (newfd == 0) { // mapping to stdin: add pid to pipe_readers
        bpf_printk("add reader: %d", pid);
	    bpf_map_update_elem(&pipe_readers, &pid, &pid, BPF_ANY);
    } else if (newfd == 1) { // mapping to stdout: add pid to pipe_writers
	    bpf_printk("add writer: %d", pid);
	    bpf_map_update_elem(&pipe_writers, &pid, &pid, BPF_ANY);
    }

    return 0;
}

// remove from pipe reader/writer maps upon fd close or process exit
SEC("kprobe/sys_enter_close")
int BPF_KPROBE(kprobe_close, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    int fd = PT_REGS_PARM1_CORE(regs);

    if (fd == 0) {
        int s = bpf_map_delete_elem(&pipe_readers, &pid);
        if (s == 0) {
            bpf_printk("close: delete reader %d", pid);
        }

	    return 0;
    } else if (fd == 1) {
        int s = bpf_map_delete_elem(&pipe_writers, &pid);
        if (s == 0) {
            bpf_printk("close: delete writer %d", pid);
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

// socket tracking (TODO: maybe move to separate C file?)
// TODO: differentiate between ipc socket and nework socket
SEC("kprobe/sys_enter_socket")
int BPF_KPROBE(kprobe_socket, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    //bpf_printk("socket");

    return 0;
}

//TODO: is there a better way to trace sockets?
SEC("kprobe/sys_enter_connect") 
int BPF_KPROBE(kprobe_connect, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    //from connect() manpage

    // int connect(int sockfd, const struct sockaddr *addr,
    //                socklen_t addrlen);

    // struct sockaddr {
    //        sa_family_t     sa_family;      /* Address family */
    //        char            sa_data[];      /* Socket address */
    //    };

    int sockfd = PT_REGS_PARM1_CORE(regs);
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2_CORE(regs);
    //struct sockaddr *sa = (struct sockaddr *)sockaddr;
    //sa_family_t family = sock_addr->sa_family;

    u16 sa_family = 0;
    bpf_probe_read(&sa_family, sizeof(sa_family), &addr->sa_family);

    if (sa_family == AF_UNIX) {
        bpf_printk("unix, pid = %d", pid);
    }

    return 0;
}

SEC("kprobe/sys_enter_accept") // find way to test this (ie programs that do IPC via unix sockets)
int BPF_KPROBE(kprobe_accept, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    bpf_printk("accept (server)");

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
