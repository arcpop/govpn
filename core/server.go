package core

import (
	"crypto/x509"
	"log"
	"net"
	"sync"

	"github.com/arcpop/govpn/cert"
)

const (
	EthernetMACHeaderLength = 14 //2 * 6 for MAC-addresses + 2 for ethertype
)

var (
	MACBroadcastAddr = MacAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
)

type clientMapKey struct {
	IP   [16]byte
	Port int
}

type Endpoint struct {
	sync.Mutex

	Name string

	macAddress    *MacAddr
	udpAddress    *net.UDPAddr
	cipherContext *SymmetricCryptoContext
}

type QueuedPacket struct {
	Addr *net.UDPAddr
	Data []byte
}

type Server struct {
	ServerMACAddress MacAddr
	ReceiveQueue     <-chan []byte
	SendQueue        chan<- []byte
	clientsLock      sync.RWMutex
	clients          map[clientMapKey]*Endpoint

	virtualSwitchLock sync.RWMutex
	virtualSwitch     map[MacAddr]*Endpoint

	serverConn *net.UDPConn

	packetQueue chan *QueuedPacket

	serverSendQueue chan []byte

	//Packets addressed to our MAC-address
	serverReceiveQueue chan []byte

	caCertificate     *x509.Certificate
	serverCertificate *cert.CertificateAndKey
}

func NewServer(serverAddr, caCertFile, serverCertFile, serverKeyFile string, ServerQueueSize int, ServerMACAddr *MacAddr) (*Server, error) {
	caCert, err := cert.ParseCertificate(caCertFile)
	if err != nil {
		return nil, err
	}
	serverCert, err := cert.ParseCertificate(serverCertFile)
	if err != nil {
		return nil, err
	}
	serverKey, err := cert.ParseKey(serverKeyFile)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{
		ServerMACAddress:   *ServerMACAddr,
		serverConn:         c,
		caCertificate:      caCert,
		serverCertificate:  &cert.CertificateAndKey{Certificate: serverCert, PrivateKey: serverKey},
		clients:            make(map[clientMapKey]*Endpoint),
		virtualSwitch:      make(map[MacAddr]*Endpoint),
		packetQueue:        make(chan *QueuedPacket, ServerQueueSize),
		serverReceiveQueue: make(chan []byte, ServerQueueSize),
		serverSendQueue:    make(chan []byte, ServerQueueSize),
	}
	s.SendQueue = s.serverSendQueue
	s.ReceiveQueue = s.serverReceiveQueue

	return s, nil
}

func (s *Server) Close() error {
	return s.serverConn.Close()
}

func (s *Server) sendWorker() {
	for p := range s.packetQueue {
		_, err := s.serverConn.WriteToUDP(p.Data, p.Addr)
		if err != nil {
			log.Println("core: server: sendWorker received send error: " + err.Error())
			return
		}
	}
}

func (s *Server) sendQueueHandler() {
	for pkt := range s.serverSendQueue {
		s.sendPacketToClients(pkt)
	}
}

func (s *Server) newClient(addr *net.UDPAddr, pkt []byte) {
	ch := ClientHelloData{}
	ok, err := s.deserializeAndVerifyClientHello(pkt, &ch)
	if err != nil {
		log.Println("core: server: failed to add new client: " + err.Error())
		return
	}
	if !ok {
		log.Println("core: server: failed to verify a new client")
		return
	}

	priv, pub, err := GenerateKeyPair(ch.CurveSelection)
	if err != nil {
		log.Println("core: server: failed generate a ecdh key for a new client: " + err.Error())
		return
	}

	secret, err := CalculateSecret(priv, ch.ClientSessionKey, ch.CurveSelection)
	if err != nil {
		log.Println("core: server: client sent invalid ecdh public key: " + err.Error())
		return
	}

	sh := ServerHelloData{
		ServerSessionKey: pub,
	}

	response, err := s.signAndSerializeServerHello(&sh)
	if err != nil {
		log.Println("core: server: failed to sign server response: " + err.Error())
		return
	}

	c := &Endpoint{
		cipherContext: &SymmetricCryptoContext{
			SymmetricCipher: ch.AEADSelection,
			SharedSecret:    secret,
			SessionNonce:    sh.SessionNonce,
		},
		Name:       ch.ClientCertificate.Subject.CommonName,
		udpAddress: addr,
	}
	s.insertClient(addr, c)
	s.packetQueue <- &QueuedPacket{Addr: addr, Data: response}
	log.Println("core: server: \"" + c.Name + "\" connected")
}

func (s *Server) handlePacket(c *Endpoint, pkt []byte) {
	p, err := decryptVPNPacket(pkt, c.cipherContext, true)
	if err != nil {
		log.Println("core: server: failed to decrypt packet: " + err.Error())
		return
	}
	if len(p) < EthernetMACHeaderLength {
		log.Println("core: server: dropping a too small packet")
		return
	}

	var destAddr, sourceAddr MacAddr
	copy(destAddr[:], p[0:6])
	copy(sourceAddr[:], p[6:12])

	if sourceAddr != MACBroadcastAddr && c.macAddress == nil {
		c.macAddress = &sourceAddr
		s.virtualSwitchLock.Lock()
		s.virtualSwitch[sourceAddr] = c
		s.virtualSwitchLock.Unlock()
	}

	if destAddr == s.ServerMACAddress {
		s.serverReceiveQueue <- p
		return
	}
	if destAddr == MACBroadcastAddr {
		s.serverReceiveQueue <- p
	}
	s.sendPacketToClients(p)
}

func (s *Server) Run() {
	go s.sendQueueHandler()
	go s.sendWorker()
	for {
		pkt := make([]byte, 2048)
		n, addr, err := s.serverConn.ReadFromUDP(pkt)
		if err != nil {
			log.Println("core: server: conn returned error: " + err.Error())
			return
		}
		pkt = pkt[:n]

		c, ok := s.getClient(addr)
		if !ok {
			go s.newClient(addr, pkt)
			continue
		}
		go s.handlePacket(c, pkt)
	}
}

func (s *Server) insertClient(addr *net.UDPAddr, c *Endpoint) {
	k := clientMapKey{Port: addr.Port}
	copy(k.IP[:], addr.IP)
	s.clientsLock.Lock()
	s.clients[k] = c
	s.clientsLock.Unlock()
}

func (s *Server) getClient(addr *net.UDPAddr) (*Endpoint, bool) {
	k := clientMapKey{Port: addr.Port}
	copy(k.IP[:], addr.IP)
	s.clientsLock.RLock()
	defer s.clientsLock.RUnlock()
	c, ok := s.clients[k]
	return c, ok
}

func (s *Server) getClientByMac(addr *MacAddr) (*Endpoint, bool) {
	s.virtualSwitchLock.RLock()
	c, ok := s.virtualSwitch[*addr]
	s.virtualSwitchLock.RUnlock()
	if ok {
		return c, ok
	}
	s.clientsLock.RLock()
	for _, k := range s.clients {
		if *k.macAddress == *addr {
			c = k
			ok = true
			break
		}
	}
	s.clientsLock.RUnlock()
	if ok {
		s.virtualSwitchLock.Lock()
		s.virtualSwitch[*addr] = c
		s.virtualSwitchLock.Unlock()
	}
	return c, ok
}

func (s *Server) sendPacketToClients(p []byte) {
	var destAddr, sourceAddr MacAddr
	copy(destAddr[:], p[0:6])
	copy(sourceAddr[:], p[6:12])

	if destAddr != MACBroadcastAddr {
		c, ok := s.getClientByMac(&destAddr)
		if ok {
			encP, err := encryptVPNPacket(p, c.cipherContext, false)
			if err != nil {
				log.Println("core: server: failed to encrypt a packet; " + err.Error())
				return
			}
			s.packetQueue <- &QueuedPacket{Addr: c.udpAddress, Data: encP}
			return
		}
	}

	s.clientsLock.RLock()
	//We make a copy so we don't block the lock while waiting for the server
	//to send all those packets
	queue := make([]*QueuedPacket, len(s.clients))
	i := 0
	for _, c := range s.clients {
		if c.macAddress != nil && *c.macAddress == sourceAddr {
			continue
		}
		encP, err := encryptVPNPacket(p, c.cipherContext, false)
		if err != nil {
			log.Println("core: server: failed to encrypt a packet; " + err.Error())
			continue
		}
		queue[i] = &QueuedPacket{Addr: c.udpAddress, Data: encP}
		i++
	}
	s.clientsLock.RUnlock()

	for j, k := range queue {
		if j == i {
			return
		}
		s.packetQueue <- k
	}
}
