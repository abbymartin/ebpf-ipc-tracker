package main

import (
    "bytes"
    "encoding/binary"
    "errors"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    //TODO: ctx? to stop things?

    // lock memory for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal("Removing memlock:", err)
    }

    var objs pipe_trackerObjects
    if err := loadPipe_trackerObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close()

    //TODO: do this smarter (https://github.com/cilium/ebpf/discussions/1186#discussioncomment-7423490)
    tps := map[string]*ebpf.Program{
	"sys_enter_write": objs.TraceWrite, 
	//"sys_enter_read": objs.TraceRead,
	"sys_enter_dup2": objs.TraceDup2,
	"sys_enter_close": objs.TraceClose,
	//"do_exit": objs.KprobeExit,
    }

    // do exit kprobe
    kp, err := link.Kprobe("do_exit", objs.KprobeExit, nil)

    if err != nil {
        log.Fatal("Opening kprobe: %s", err)
    }
    defer kp.Close()

    tp, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceRead, nil);
    if err != nil {
        log.Fatal("Opening read: %s", err)
    }
    defer tp.Close()

    // attach tracepoints
    for fn, prog := range(tps) {
	tp, err := link.Tracepoint("syscalls", fn, prog, nil)

	if err != nil {
	    log.Fatal("Opening tracepoint: %s", err)
	}
	defer tp.Close()
    }
    
    // ringbuf reader
    rd, err := ringbuf.NewReader(objs.PipeWrites)
    if err != nil {
	log.Fatalf("opening ringbuf reader %s", err)
    }
    defer rd.Close()

    rd2, err := ringbuf.NewReader(objs.PipeReads)
    if err != nil {
        log.Fatalf("opening ringbuf reader %s", err)
    }
    defer rd2.Close()

    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

    go func() {
	<-stop // wait for SIGINT signal

	if err := rd.Close(); err != nil {
	    log.Fatalf("closing ringbuf reader: %s", err)
	}
    }()

    log.Println("waiting.....")

    var event pipe_trackerEvent
    for {
	record, err := rd.Read()
	//record2, err2 := rd2.Read()

	if err != nil {
	    if errors.Is(err, ringbuf.ErrClosed) {
       		log.Println("received signal, exiting..")
		return
	    }
	    log.Printf("reading from reader: %s", err)
	    continue
    	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
	    log.Printf("parsing ringbuf event %s", err)
	    continue
	}

	log.Printf("PIPE WRITE: pid: %d, ts: %d", event.Pid, event.Ts)
    }
}
