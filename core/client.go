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

	serverUDPAddr     *net.UDPAddr
	conn              *net.UDPConn
	clientCertificate *cert.CertificateAndKey
	serverCertificate *x509.Certificate
	cryptoContext     *SymmetricCryptoContext
	dhPublicKey       []byte
	dhPrivateKey      []byte
	handshakeDone     bool
}

func NewClient(ClientCertFile, ClientKeyFile, ServerCertFile string) (*Client, error) {
	serverCert, err := parseCertificate(ServerCertFile)
	if err != nil {
		return nil, err
	}
	clientCert, err := parseCertificate(ClientCertFile)
	if err != nil {
		return nil, err
	}
	clientKey, err := parseKey(ClientKeyFile)
	if err != nil {
		return nil, err
	}

	return &Client{
		handshakeDone:     false,
		cryptoContext:     &SymmetricCryptoContext{NonceCounter: 0},
		clientCertificate: &CertificateAndKey{Certificate: clientCert, PrivateKey: clientKey},
		serverCertificate: serverCert,
	}, nil
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
	c.handshakeDone = true
	log.Println("core: client: connected to server")
	return nil
}

func (c *Client) Run(packetConsumer chan<- []byte) {
	c.Lock()
	if !c.handshakeDone {
		c.Unlock()
		return
	}
	c.conn.SetReadDeadline(time.Time{})
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
			log.Println("core: client: failed to decrypt a packet")
			return
		}
		packetConsumer <- p
	}
}

func (c *Client) RunBackground(packetConsumer chan<- []byte) {
	go c.Run(packetConsumer)
}
