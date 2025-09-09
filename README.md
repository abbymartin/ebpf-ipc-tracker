Tracking inter-process communication by hooking into syscalls using eBPF. Kernel programs written in C using libbpf and user-space program in Go using Cilium's ebpf-go library.

Pipe Tracing:
- Pipe2: fexit hook to track file descriptors after pipe has been created
- Dup2: update tracked pipereaders/pipewriters when pipe fds are re-mapped to stdout and stdin
- Read/write: trace reads/writes from known pipe fds
- Close/exit: remove pid and fd from pipereaders/pipewriters

Socket Tracing (in progress):
- Tracing socket syscalls - socket, connect, accept, sendmsg, recvmsg
- Filtering for only AF_UNIX sockets
