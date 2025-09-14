//go:build ignore

#define AF_UNIX 1

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