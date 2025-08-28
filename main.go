package main

import (
    "bytes"
    "encoding/binary"
    "errors"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    //TODO: ctx? to stop things?

    //TODO: cleanup
    fn := "sys_write"
    fn1 := "sys_read"
    fn2 := "sys_dup2"
    fn3 := "sys_close"
    fn4 := "do_exit"

    // lock memory for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal("Removing memlock:", err)
    }

    var objs pipe_trackerObjects
    if err := loadPipe_trackerObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close()

    // attach count_packets
    kp, err := link.Kprobe(fn, objs.KprobeWrite, nil)

    if err != nil {
	log.Fatal("Opening kprobe: %s", err)
    }
    defer kp.Close()

    kp1, err := link.Kprobe(fn1, objs.KprobeRead, nil)
    if err != nil {
        log.Fatal("Opening kprobe: %s", err)
    }
    defer kp1.Close()

    kp2, err := link.Kprobe(fn2, objs.KprobeDup2, nil)
    if err != nil {
        log.Fatal("Opening kprobe: %s", err)
    }
    defer kp2.Close()

    kp3, err := link.Kprobe(fn3, objs.KprobeClose, nil)
    if err != nil {
        log.Fatal("Opening kprobe: %s", err)
    }
    defer kp3.Close()

    kp4, err := link.Kprobe(fn4, objs.KprobeExit, nil)
    if err != nil {
	log.Fatal("Opening kprobe: %s", err)
    }
    defer kp4.Close()

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
