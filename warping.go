package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"golang.zx2c4.com/wireguard/device"
)

type Warping struct {
	maxCnt     int
	maxPing    int
	maxThreads int

	bar       *progressbar.ProgressBar
	probes    []*Probe
	results   []*Result
	handshake []byte

	sync.Mutex
}

func NewWarping(threads, cnt int, quickMode bool) *Warping {
	maxCnt := 0
	if quickMode {
		maxCnt = 2048
	}
	return &Warping{
		maxCnt:     maxCnt,
		maxPing:    cnt,
		maxThreads: threads,
		probes:     make([]*Probe, 0, 2048),
		results:    make([]*Result, 0, 2048),
		handshake:  warpHandshakePacket,
	}
}

func (w *Warping) SetHandshakePacket(pubKey, priKey string) error {
	noisePriKey, _ := getNoisePrivateKeyFromBase64(priKey)
	noisePubKey, _ := getNoisePublicKeyFromBase64(pubKey)
	pkt, err := buildHandshakePacket(noisePriKey, noisePubKey)
	if err != nil {
		return err
	}
	w.handshake = pkt
	return nil
}

func (w *Warping) Run() {
	// 0. init possible targets
	w.generateProbes()
	if w.maxCnt > 0 && len(w.probes) > w.maxCnt {
		w.probes = w.probes[:w.maxCnt]
	}
	color.Green("[*] we have %d combo to tests", len(w.probes))

	// 1. init probe runner
	var wg sync.WaitGroup
	probeCh := make(chan *Probe, w.maxThreads)
	wg.Add(w.maxThreads)
	for i := 0; i < w.maxThreads; i++ {
		go func() {
			defer wg.Done()
			for p := range probeCh {
				w.probeRunner(p)
			}
		}()
	}

	color.Green("[*] %d gorountines running", w.maxThreads)
	fmt.Println()
	w.bar = progressbar.Default(int64(len(w.probes)))

	// 2. serve the probe to the runner
	for _, p := range w.probes {
		probeCh <- p
	}
	close(probeCh)
	wg.Wait()
	w.bar.Finish()

	// 3. print and export result
	fmt.Println()
	w.sortAndExportResult()
}

func (w *Warping) generateProbes() {
	rand.Shuffle(len(warpCIDRs), func(i, j int) { warpCIDRs[i], warpCIDRs[j] = warpCIDRs[j], warpCIDRs[i] })
	for _, cidr := range warpCIDRs {
		ips, err := GenerateIPsFromCIDR(cidr)
		if err != nil {
			log.Printf("func `GenerateIPsFromCIDR` failed, detail: %s", err)
			continue
		}
		rand.Shuffle(len(warpPorts), func(i, j int) { warpPorts[i], warpPorts[j] = warpPorts[j], warpPorts[i] })
		for _, port := range warpPorts {
			w.probes = append(w.probes, GenerateProbes(ips, port)...)
			if w.maxCnt > 0 && len(w.probes) > w.maxCnt {
				break
			}
		}
	}

	// shuffle func
	rand.Shuffle(len(w.probes), func(i, j int) { w.probes[i], w.probes[j] = w.probes[j], w.probes[i] })
}

func (w *Warping) probeRunner(p *Probe) {
	endpoint := fmt.Sprintf("%s:%d", p.ip.String(), p.port)
	if p.ip.To4() == nil {
		endpoint = fmt.Sprintf("[%s]:%d", p.ip.String(), p.port)
	}
	res := &Result{endpoint: endpoint}
	conn, err := net.DialTimeout("udp", endpoint, connTimeout)
	if err != nil {
		return
	}
	defer conn.Close()

	for i := 0; i < w.maxPing; i++ {
		ok, rtt := handshake(conn, w.handshake)
		if ok {
			res.recvCnt++
			res.totalDuration += rtt
		}
	}

	if res.recvCnt <= 0 {
		return
	}

	w.Lock()
	w.results = append(w.results, res)
	w.Unlock()

	if w.bar != nil {
		w.bar.Add(1)
	}

	res.loss = (w.maxPing - res.recvCnt) * 1e4 / w.maxPing
	res.latency = res.totalDuration.Milliseconds() / int64(res.recvCnt)
	//color.Blue("<%s> \t%.2f%% \tavg: %dms\n", endpoint, float64(res.loss)/100, res.latency)
}

func (w *Warping) sortAndExportResult() {
	// sort result, loss rate first
	sort.Slice(w.results, func(i, j int) bool {
		if w.results[i].loss == w.results[j].loss {
			return w.results[i].latency < w.results[j].latency
		}
		return w.results[i].loss < w.results[j].loss
	})

	// final result
	cnt := 10
	for idx, res := range w.results {
		color.Cyan("#%2d: <%s> \t%.2f%% \tavg: %dms\n", idx+1, res.endpoint, float64(res.loss)/100, res.latency)
		cnt -= 1
		if cnt <= 0 {
			break
		}
	}
}

func handshake(conn net.Conn, packets []byte) (bool, time.Duration) {
	startTime := time.Now()
	_, err := conn.Write(packets)
	if err != nil {
		return false, 0
	}

	revBuff := make([]byte, 1024)

	err = conn.SetDeadline(time.Now().Add(connTimeout))
	if err != nil {
		return false, 0
	}
	n, err := conn.Read(revBuff)
	if err != nil {
		return false, 0
	}
	if n != device.MessageResponseSize {
		return false, 0
	}

	duration := time.Since(startTime)
	return true, duration
}
