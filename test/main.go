package main

import (
	"fmt"
	"log"

	"github.com/arcpop/govpn/core"
)

func main() {
	s, err := core.NewServer(
		"localhost:26666",
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

	recvQueue := make(chan []byte)
	c1.RunBackground(recvQueue)

	go func(q <-chan []byte) {
		for p := range q {
			fmt.Printf("c1 received: %+v\n", p)
		}
	}(recvQueue)

}
