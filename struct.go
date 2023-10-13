package main

import (
	"net"
	"time"
)

type Probe struct {
	ip   *net.IP
	port int
}

type Result struct {
	endpoint      string
	loss          int // x 1e4
	latency       int64
	recvCnt       int
	totalDuration time.Duration
}
