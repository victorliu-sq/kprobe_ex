package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)

func main() {
	// Load the eBPF obj
	bpfModule, err := bpf.NewModuleFromFile("simple.bpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()

	// Find the bpf program
	prog, err := bpfModule.GetProgram("kprobe__sys_execve")
	if err != nil {
		os.Exit(-1)
	}
	// Attach the hook to a specific function
	_, err = prog.AttachKprobe("__x64_sys_execve")
	if err != nil {
		os.Exit(-1)
	}
	// Initialize the ring buffer
	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	// Start the agent adn read events from the channel
	rb.Start()

	for {
		event := <-eventsChannel
		pid := int(binary.LittleEndian.Uint32(event[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		comm := string(bytes.TrimRight(event[4:], "\x00")) // Remove excess 0's from comm, treat as string
		fmt.Printf("%d %v\n", pid, comm)
	}

	rb.Stop()
	rb.Close()
}
