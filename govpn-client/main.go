package main

import (
	"flag"
	"log"

	"github.com/arcpop/govpn/adapter"
	"github.com/arcpop/govpn/core"
)

var (
	ServerAddress  string
	ClientCertFile string
	ClientKeyFile  string
	ServerCertFile string
	CurveType      string
	AEADType       string
)

func init() {
	flag.StringVar(&ServerAddress, "server", "localhost:666", "Address and port of server")
	flag.StringVar(&ClientCertFile, "clientcert", "client.pem", "File with client certificate")
	flag.StringVar(&ClientKeyFile, "clientkey", "client.key", "File with client private key")
	flag.StringVar(&ServerCertFile, "servercert", "server.pem", "File with server certificate")
	flag.StringVar(&CurveType, "curve", "P25519", "Curve for ECDH. Valid choices: P25519, P256, P384, P521")
	flag.StringVar(&AEADType, "cipher", "AES256-GCM", "Cipher for encryption. Choices: AES128-GCM, AES256-GCM, ChaCha20Poly1305")
	flag.Parse()
}

func main() {
	var c core.CurveType
	var a core.AEADType
	switch CurveType {
	case "P25519":
		c = core.Curve25519
	case "P256":
		c = core.P256
	case "P384":
		c = core.P384
	case "P521":
		c = core.P521
	default:
		log.Fatal("Invalid curve type.")
		return
	}
	switch AEADType {
	case "AES128-GCM":
		a = core.Aes128Gcm
	case "AES256-GCM":
		a = core.Aes256Gcm
	case "ChaCha20Poly1305":
		a = core.Chacha20Poly1305
	default:
		log.Fatal("Invalid cipher type.")
		return
	}

	inst, err := adapter.NewTAP("tap0", 1450)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer inst.Close()

	client, err := core.NewClient(ServerAddress, ClientCertFile, ClientKeyFile, ServerCertFile)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer client.Close()

	err = client.PerformHandshake(a, c)
	if err != nil {
		log.Fatal(err)
		return
	}

	log.Println("Connected to server")

	client.RunBackground()

	go tapToServerWorker(client, inst)
	serverToTapWorker(client, inst)
}

func tapToServerWorker(client *core.Client, inst adapter.Instance) {
	channel := inst.ReceiveChannel()
	for pkt, ok := <-channel; ok; pkt, ok = <-channel {
		client.SendQueue <- pkt
	}
}

func serverToTapWorker(client *core.Client, inst adapter.Instance) {
	channel := inst.TransmitChannel()
	for pkt, ok := <-client.ReceiveQueue; ok; pkt, ok = <-client.ReceiveQueue {
		channel <- pkt
	}
}
