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

//type Event struct {
    //Pid uint32
  //  Fd int
 //   Ts uint32
//    Comm [16]byte
//}

func main() {
    fn := "sys_write"
    fn2 := "sys_dup2"

    // lock memory for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatal("Removing memlock:", err)
    }

    var objs pipe_trackerObjects
    if err := loadPipe_trackerObjects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close() // close at end of function?

    // attach count_packets
    kp, err := link.Kprobe(fn, objs.KprobeWrite, nil)

    if err != nil {
	log.Fatal("Opening kprobe: %s", err)
    }
    defer kp.Close()

    kp2, err := link.Kprobe(fn2, objs.KprobeDup2, nil)
    if err != nil {
        log.Fatal("Opening kprobe: %s", err)
    }
    defer kp2.Close()

    // ringbuf reader
    rd, err := ringbuf.NewReader(objs.Writes)
    if err != nil {
	log.Fatalf("opening ringbuf reader %s", err)
    }
    defer rd.Close()
    // log.Printf("Counting incoming packets on %s..", ifname)

    //tick := time.Tick(time.Second)
    stop := make(chan os.Signal, 5)
    signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

    go func() {
	<-stop

	if err := rd.Close(); err != nil {
	    log.Fatalf("closing ringbuf reader: %s", err)
	}
    }()

    log.Println("waiting.....")

    var event pipe_trackerEvent
    for {
	record, err := rd.Read()

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

	log.Printf("pid: %d, fd: %d", event.Pid, event.Fd)
    }
    
}
