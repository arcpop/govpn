package main

import (
	"fmt"
	"log"

	"github.com/arcpop/govpn/core"
)

var (
	p1 = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0x00, 0x30}
	p2 = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xFF, 0xE1, 0xAA, 0xBB, 0x00, 0x30}
)

func main() {
	s, err := core.NewServer(
		":6666",
		"ca.pem",
		"server.pem",
		"server.key",
		1024,
		&core.MacAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	)
	if err != nil {
		log.Fatal(err)
		return
	}
	go s.Run()

	c1, err := core.NewClient(
		"localhost:6666",
		"client.pem",
		"client.key",
		"server.pem",
	)
	if err != nil {
		log.Fatal(err)
		return
	}

	err = c1.PerformHandshake(core.Aes128Gcm, core.Curve25519)
	if err != nil {
		log.Fatal(err)
		return
	}

	c1.RunBackground()

	go func(q <-chan []byte) {
		for p := range q {
			fmt.Printf("c1 received: %+v\n", p)
		}
	}(c1.ReceiveQueue)
	s.SendQueue <- p1
	c1.SendQueue <- p2
	p := <-s.ReceiveQueue
	fmt.Printf("server received: %+v\n", p)
}
