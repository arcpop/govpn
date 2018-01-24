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
	Network    string
)

func init() {
	flag.StringVar(&ServerAddr, "server", "localhost:666", "Server listen address")
	flag.StringVar(&Network, "net", "udp", "udp or tcp")
}

var Counter uint64

func handleSpeedtestClient(c net.Conn) {
	buf := make([]byte, 1000)
	for n, err := c.Read(buf); err == nil; n, err = c.Read(buf) {
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
	l, err := net.Listen(Network, ServerAddr)
	if err != nil {
		log.Fatal(err)
		return
	}

	go printResults()
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
			return
		}
		go handleSpeedtestClient(c)
	}
}
