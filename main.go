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
    kprobes := map[string]*ebpf.Program{
	"sys_write": objs.KprobeWrite, 
	"sys_read": objs.KprobeRead,
	"sys_dup2": objs.KprobeDup2,
	"sys_close": objs.KprobeClose,
	"do_exit": objs.KprobeExit,
    }

    // attach kprobes
    for fn, probe := range(kprobes) {
	kp, err := link.Kprobe(fn, probe, nil)

	if err != nil {
	    log.Fatal("Opening kprobe: %s", err)
	}
	defer kp.Close()
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
