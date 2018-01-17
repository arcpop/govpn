package main

import (
	"flag"
	"log"

	"github.com/arcpop/govpn/adapter"
	"github.com/arcpop/govpn/core"
)

var (
	ServerAddress  string
	CACertFile     string
	ServerCertFile string
	ServerKeyFile  string
	QueueSize      int
)

func init() {
	flag.StringVar(&ServerAddress, "server", "localhost:666", "Address and port of server")
	flag.StringVar(&CACertFile, "cacert", "ca.pem", "File with CA certificate")
	flag.StringVar(&ServerCertFile, "servercert", "server.pem", "File with server certificate")
	flag.StringVar(&ServerKeyFile, "serverkey", "server.key", "File with server private key")
	flag.IntVar(&QueueSize, "queuesize", 1024, "The size of the server packet queue")
	flag.Parse()
}

func main() {
	inst, err := adapter.NewTAP("tap0", 1450)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer inst.Close()

	server, err := core.NewServer(ServerAddress, CACertFile, ServerCertFile, ServerKeyFile, QueueSize, inst.GetMACAddress())
	if err != nil {
		log.Fatal(err)
		return
	}
	defer server.Close()

	go tapToServerWorker(server, inst)
	go serverToTapWorker(server, inst)
	server.Run()
}

func tapToServerWorker(server *core.Server, inst adapter.Instance) {
	channel := inst.ReceiveChannel()
	for pkt, ok := <-channel; ok; pkt, ok = <-channel {
		server.SendQueue <- pkt
	}
}

func serverToTapWorker(server *core.Server, inst adapter.Instance) {
	channel := inst.TransmitChannel()
	for pkt, ok := <-server.ReceiveQueue; ok; pkt, ok = <-server.ReceiveQueue {
		channel <- pkt
	}
}
