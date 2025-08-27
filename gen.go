package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -tags linux pipe_tracker pipe_tracker.c
