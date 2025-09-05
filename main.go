package main

import (
    "bytes"
    "encoding/binary"
    "errors"
    "log"
    "os"
    "os/signal"
    "syscall"
    "fmt"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // unlock memory for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal("Removing memlock:", err)
    }

    var objs pipe_trackerObjects
    if err := loadPipe_trackerObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close()

    //TODO: do this smarter (https://github.com/cilium/ebpf/discussions/1186#discussioncomment-7423490)
    kprobes := map[string]*ebpf.Program{
        "sys_write": objs.KprobeWrite, 
        "sys_read": objs.KprobeRead,
        "sys_dup2": objs.KprobeDup2,
        "sys_close": objs.KprobeClose,
        "do_exit": objs.KprobeExit,
        "sys_socket": objs.KprobeSocket,
        "sys_connect": objs.KprobeConnect,
        "sys_accept": objs.KprobeAccept,
    }

    // attach kprobes
    for fn, probe := range(kprobes) {
        kp, err := link.Kprobe(fn, probe, nil)

        if err != nil {
            log.Fatal("Opening kprobe: %s", err)
        }
        defer kp.Close()
    }
    
    // reader for ebpf pipe events
    rd, err := ringbuf.NewReader(objs.PipeEvents)
    if err != nil {
	    log.Fatalf("Opening ringbuf reader %s", err)
    }
    defer rd.Close()

    // terminate signal
    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

    events := make(chan string)

    log.Println("Waiting...")

    // Goroutine for pipe events
    go func() {
        var event pipe_trackerEvent
        for {
            record, err := rd.Read()

            if err != nil {
                if errors.Is(err, ringbuf.ErrClosed) {
                    return
                }
                log.Printf("Error reading from reader: %s", err)
                continue
            }

            if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
                log.Printf("Error parsing ringbuf event %s", err)
                continue
            }

            events <- fmt.Sprintf("PIPE EVENT: pid: %d, ts: %d, type: %c", event.Pid, event.Ts, event.Type)
        }
    }()

    for {
        select {
		case out := <-events:
			fmt.Println(out)
		case <-stop:
            if err := rd.Close(); err != nil {
                log.Fatalf("Closing ringbuf reader: %s", err)
            }
			fmt.Println("Exiting...")
			return
        }
    }
}
