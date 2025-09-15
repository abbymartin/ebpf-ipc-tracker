//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define STDIN 0
#define STDOUT 1
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
    __type(value, int); // value: fd
} pipe_writers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, u32); // key: pid
    __type(value, int); // value: fd
} pipe_readers SEC(".maps");

// map to keep track of fds we know are pipes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, int); // key: fd
    __type(value, u32); // value: pid
} pipe_fds SEC(".maps");

// TODO: change to tracepoints where possible (more efficient than kprobes)
// ^ kernel bug w perf may be causing issues https://bugs.launchpad.net/ubuntu/+source/linux-hwe-6.14/+bug/2117159

// TODO: cannot handle multiple pipes within same process or series of pipes (ls | grep a | grep b) due to hashmap setup only allowing 1 read and 1 write end per pid
SEC("fexit/do_pipe2")
int BPF_PROG(pipe2, int *filedes, int ret) {
    if (ret != 0)
        return 0;

    u32 pid = bpf_get_current_pid_tgid();

    int fds[2];
    bpf_probe_read_user(&fds, sizeof(fds), filedes);

    // add initial pipe fds to pipe_readers/pipe_writers to cover bases, removed upon re-map
    bpf_map_update_elem(&pipe_fds, &fds[0], &pid, BPF_ANY);
    bpf_map_update_elem(&pipe_readers, &pid, &fds[0], BPF_ANY);
    bpf_printk("pipe2: adding reader: %d, pid: %d", fds[0], pid);

    bpf_map_update_elem(&pipe_fds, &fds[1], &pid, BPF_ANY);
    bpf_map_update_elem(&pipe_writers, &pid, &fds[1], BPF_ANY);
    bpf_printk("pipe2: adding writer %d, pid: %d", fds[1], pid);
    return 0;
}

// pipe setup uses dup2 syscall to map stdout or stdin to pipe fds (makes possible to exec w pipe)
SEC("kprobe/sys_enter_dup2")
int BPF_KPROBE(kprobe_dup2, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    int oldfd = PT_REGS_PARM1_CORE(regs);
    int newfd = PT_REGS_PARM2_CORE(regs);
    //bpf_printk("old: %d, new: %d", oldfd, newfd);

    // make sure we are mapping a pipe fd
    u32 *oldpid = bpf_map_lookup_elem(&pipe_fds, &oldfd);
    if(!oldpid) {
        return 0;
    }
    
    // Q: will a pipe ever map to something other than STDIN or STDOUT?
    if (newfd == STDIN) { // mapping to stdin: add pid to pipe_readers
        // remove old pipe_reader
        int s = bpf_map_delete_elem(&pipe_readers, &oldpid);
        if (!s) {
            bpf_printk("dup2: delete reader %d, fd: %d", pid, oldfd);
        }

        bpf_printk("dup2: map reader %d to %d for pid: %d", oldfd, newfd, pid);
	    bpf_map_update_elem(&pipe_readers, &pid, &newfd, BPF_ANY);
    } else if (newfd == STDOUT) { // mapping to stdout: add pid to pipe_writers
        // remove old pipe_writer
        int s = bpf_map_delete_elem(&pipe_writers, &oldpid);
        if (!s) {
            bpf_printk("dup2: delete writer %d, fd: %d", pid, oldfd);
        }

        bpf_printk("dup2: map writer %d to %d for pid: %d", oldfd, newfd, pid);
	    bpf_map_update_elem(&pipe_writers, &pid, &newfd, BPF_ANY);
    }

    bpf_map_delete_elem(&pipe_fds, &oldfd);

    return 0;
}

SEC("kprobe/sys_enter_read")
int BPF_KPROBE(kprobe_read, struct pt_regs *regs) {
    struct event *e;

    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    int fd = PT_REGS_PARM1_CORE(regs);

    // check if pid is in pipe_readers
    int *pipe_fd = bpf_map_lookup_elem(&pipe_readers, &pid);
    if (!pipe_fd || *pipe_fd != fd) {
        return 0;
    }

    bpf_printk("read: fd: %d, pipe_fd: %d", fd, *pipe_fd);

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
    int fd = PT_REGS_PARM1_CORE(regs);
    
    // check if pid is in pipe_writers
    int *pipe_fd = bpf_map_lookup_elem(&pipe_writers, &pid);
    if (!pipe_fd || *pipe_fd != fd) {
        return 0;
    }

    bpf_printk("write: fd: %d, pipe_fd: %d", fd, *pipe_fd);
    
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


    if (reader_fd && *reader_fd == fd) {
        int s = bpf_map_delete_elem(&pipe_readers, &pid);
        if (!s) {
            bpf_printk("close: delete reader %d, fd: %d", pid, *reader_fd);
        }
    } else if (writer_fd && *writer_fd == fd) {
        int s = bpf_map_delete_elem(&pipe_writers, &pid);
        if (!s) {
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

// Unix socket tracing

// *server steps*
// socket() -> bind() -> listen() -> accept()
// *client steps*
// socket() -> connect()

SEC("kprobe/sys_enter_socket")
int BPF_KPROBE(kprobe_socket, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();
    int domain = PT_REGS_PARM1_CORE(regs);
    if (domain == AF_UNIX) {
        bpf_printk("socket: unix, pid = %d", pid);
    }
    
    return 0;
}

SEC("kprobe/sys_enter_connect") 
int BPF_KPROBE(kprobe_connect, struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid();

    // struct sockaddr {
    //        sa_family_t     sa_family;      /* Address family */
    //        char            sa_data[];      /* Socket address */
    //    };

    int sockfd = PT_REGS_PARM1_CORE(regs);
    struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2_CORE(regs);
    
    // null check
    if(!addr) return 0;

    u16 sa_family = 0;
    bpf_probe_read(&sa_family, sizeof(sa_family), &addr->sa_family);

    if (sa_family == AF_UNIX) {
        bpf_printk("connect: unix, pid = %d, family=%d", pid, sa_family);
    }

    return 0;
}

SEC("fexit/__sys_accept4")
int BPF_PROG(accept, int sockfd, struct sockaddr *addr, int *addrlen, int ret) { // Q: double check this function signature
    u32 pid = bpf_get_current_pid_tgid();

    // null check
    if (!addr) return 0;
    u16 sa_family = 0;
    bpf_probe_read(&sa_family, sizeof(sa_family), &addr->sa_family);

    if (sa_family == AF_UNIX) {
        bpf_printk("accept: unix, pid = %d, family=%d", pid, sa_family);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
