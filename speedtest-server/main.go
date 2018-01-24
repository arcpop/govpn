package main

import (
	"flag"
	"log"
	"net"
	"sync/atomic"
	"time"
)

var (
	ServerAddr string
)

func init() {
	flag.StringVar(&ServerAddr, "server", "localhost:666", "Server listen address")
}

var Counter uint64

func handleSpeedtestClient(c *net.UDPConn) {
	buf := make([]byte, 1000)
	for n, _, err := c.ReadFromUDP(buf); err == nil; n, _, err = c.ReadFromUDP(buf) {
		var t uint64
		t = uint64(n)
		atomic.AddUint64(&Counter, t)
	}
}

func printResults() {
	t := time.NewTicker(time.Second)
	for _ = range t.C {
		r := atomic.SwapUint64(&Counter, 0)
		log.Println(r)
	}
}

func main() {
	flag.Parse()
	addr, err := net.ResolveUDPAddr("udp", ServerAddr)
	if err != nil {
		log.Fatal(err)
		return
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
		return
	}

	go printResults()
	handleSpeedtestClient(c)
}
