package core

import (
	"crypto/x509"
	"log"
	"net"
	"sync"
	"time"

	"github.com/arcpop/govpn/cert"
)

type Client struct {
	sync.Mutex

	ServerAddress string
	SendQueue     chan<- []byte
	ReceiveQueue  <-chan []byte

	clientToServerQueue chan []byte
	clientReceiveQueue  chan []byte

	stopReadWorker  chan interface{}
	stopWriteWorker chan interface{}

	serverUDPAddr     *net.UDPAddr
	conn              *net.UDPConn
	clientCertificate *cert.CertificateAndKey
	serverCertificate *x509.Certificate
	cryptoContext     *SymmetricCryptoContext
	dhPublicKey       []byte
	dhPrivateKey      []byte
	handshakeDone     bool
}

func NewClient(ServerAddr, ClientCertFile, ClientKeyFile, ServerCertFile string) (*Client, error) {
	serverCert, err := cert.ParseCertificate(ServerCertFile)
	if err != nil {
		return nil, err
	}
	clientCert, err := cert.ParseCertificate(ClientCertFile)
	if err != nil {
		return nil, err
	}
	clientKey, err := cert.ParseKey(ClientKeyFile)
	if err != nil {
		return nil, err
	}

	c := &Client{
		handshakeDone:       false,
		ServerAddress:       ServerAddr,
		cryptoContext:       &SymmetricCryptoContext{NonceCounter: 0},
		clientCertificate:   &cert.CertificateAndKey{Certificate: clientCert, PrivateKey: clientKey},
		serverCertificate:   serverCert,
		clientReceiveQueue:  make(chan []byte, 1024),
		clientToServerQueue: make(chan []byte, 1024),
		stopReadWorker:      make(chan interface{}, 1),
		stopWriteWorker:     make(chan interface{}, 1),
	}
	c.SendQueue = c.clientToServerQueue
	c.ReceiveQueue = c.clientReceiveQueue
	return c, nil
}

func (c *Client) PerformHandshake(cipherType AEADType, curveType CurveType) error {
	c.Lock()
	defer c.Unlock()

	if c.handshakeDone {
		return nil
	}

	var err error
	c.dhPrivateKey, c.dhPublicKey, err = GenerateKeyPair(curveType)
	if err != nil {
		return err
	}

	ch := ClientHelloData{
		AEADSelection:  cipherType,
		CurveSelection: curveType,
	}

	pkt, err := c.signAndSerializeClientHello(&ch, c.dhPublicKey)
	if err != nil {
		return err
	}

	if c.serverUDPAddr == nil {
		c.serverUDPAddr, err = net.ResolveUDPAddr("udp", c.ServerAddress)
		if err != nil {
			return err
		}
	}
	c.conn, err = net.DialUDP("udp", nil, c.serverUDPAddr)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(pkt)
	if err != nil {
		c.conn.Close()
		return err
	}

	pkt = make([]byte, 2048)
	c.conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	_, err = c.conn.Read(pkt)
	if err != nil {
		c.conn.Close()
		return err
	}
	sh := ServerHelloData{}
	verificationOk, err := c.deserializeAndVerifyServerHello(pkt, &sh)
	if err != nil {
		c.conn.Close()
		return err
	}
	if !verificationOk {
		c.conn.Close()
		log.Println("core: client: failed to verify server certificate")
		return ErrInvalidCertificate
	}

	c.cryptoContext.SharedSecret, err = CalculateSecret(c.dhPrivateKey, sh.ServerSessionKey, curveType)
	if err != nil {
		c.conn.Close()
		return err
	}
	copy(c.cryptoContext.SessionNonce[:], sh.SessionNonce[:])
	c.handshakeDone = true
	log.Println("core: client: connected to server")
	return nil
}

func (c *Client) Close() error {
	c.stopReadWorker <- 1
	c.stopWriteWorker <- 1
	return c.conn.Close()
}

func (c *Client) sendWorker() {
	for pkt := range c.clientToServerQueue {
		p, err := encryptVPNPacket(pkt, c.cryptoContext, true)
		if err != nil {
			log.Println("core: client: failed to encrypt a packet: ", err)
			continue
		}
		c.conn.Write(p)
	}
}
func (c *Client) Run() {
	c.Lock()
	if !c.handshakeDone {
		c.Unlock()
		return
	}
	c.conn.SetWriteDeadline(time.Time{})
	c.conn.SetReadDeadline(time.Time{})
	go c.sendWorker()
	c.Unlock()
	for {
		pkt := make([]byte, 2048)
		n, err := c.conn.Read(pkt)
		if err != nil {
			log.Println("core: client: error from reading udp conn")
			return
		}
		p, err := decryptVPNPacket(pkt[:n], c.cryptoContext, false)
		if err != nil {
			log.Println("core: client: failed to decrypt a packet: ", err)
			return
		}
		c.clientReceiveQueue <- p
	}
}

func (c *Client) RunBackground() {
	go c.Run()
}
