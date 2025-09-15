# eBPF Inter-process Communication Tracker

Tracing different methods of inter-process communication in Linux by hooking into syscalls using eBPF (Extended Berkeley Packet Filter). Kernel program is written in C using libbpf and user-space program is written in Go using Cilium's [ebpf-go](https://github.com/cilium/ebpf) library.

Pipe Tracing:
- Pipe2: fexit hook to retrieve file descriptors after pipe has been created and store in hashmap data structure
- Dup2: update tracked pipe_readers/pipe_writers when pipe fds are re-mapped to stdout and stdin
- Read/write: record reads/writes from known pipe fds in a ringbuffer to be read by Go program
- Close/exit: remove pid and fd from pipereaders/pipewriters when needed

Socket Tracing (in progress):
- Tracing socket syscalls - socket, connect, accept, sendmsg, recvmsg
- Filtering for only AF_UNIX sockets

`vmlinux.h` was generated on Ubuntu 24.04 with kernel 6.14. To regenerate for another kernel:
`bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`

Minimum kernel version of **5.5** required to support fexit probes.
