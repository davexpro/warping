package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Warping struct {
	maxCnt     int
	maxPing    int
	maxThreads int

	probes    []*Probe
	results   []*Result
	handshake []byte

	sync.Mutex
}

func NewWarping() *Warping {
	priKey, _ := wgtypes.GeneratePrivateKey()
	noisePriKey, _ := getNoisePrivateKeyFromBase64(priKey.String())
	noisePubKey, _ := getNoisePublicKeyFromBase64(WarpPublicKey)
	pkt := buildHandshakePacket(noisePriKey, noisePubKey)
	fmt.Println(base64.StdEncoding.EncodeToString(pkt))
	fmt.Println(base64.StdEncoding.EncodeToString(warpHandshakePacket))
	return &Warping{
		maxPing:    20,
		maxCnt:     5000,
		maxThreads: 32,
		probes:     make([]*Probe, 0, 2048),
		results:    make([]*Result, 0, 2048),
		handshake:  pkt,
	}
}

func (w *Warping) Run() {

	w.generateProbes()
	log.Printf("[*] we have %d combo to tests", len(w.probes))

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

	log.Printf("[*] %d gorountines running", w.maxThreads)

	for _, p := range w.probes {
		probeCh <- p
	}
	close(probeCh)
	wg.Wait()

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
	rand.New(rand.NewSource(time.Now().UnixNano()))
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
		ok, rtt := handshake(conn, warpHandshakePacket)
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

	res.loss = (w.maxPing - res.recvCnt) * 1e4 / w.maxPing
	res.latency = res.totalDuration.Milliseconds() / int64(res.recvCnt)
	fmt.Printf("<%s> \t%.2f%% \tavg: %dms\n", endpoint, float64(res.loss)/100, res.latency)
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
	cnt := 50
	fmt.Println("================================================================")
	fmt.Println("================================================================")
	fmt.Println("================================================================")
	for _, res := range w.results {
		fmt.Printf("<%s> \t%.2f%% \tavg: %dms\n", res.endpoint, float64(res.loss)/100, res.latency)
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
	if n != wireguardHandshakeRespBytes {
		return false, 0
	}

	duration := time.Since(startTime)
	return true, duration
}
