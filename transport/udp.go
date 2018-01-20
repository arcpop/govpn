package transport

import (
	"net"
)

type udpPacketData struct {
	a *net.UDPAddr
	p []byte
}

type udpChannel struct {
	c            *net.UDPConn
	sendQueue    chan *udpPacketData
	receiveQueue chan *udpPacketData
}

func NewUDP(Net, ServerAddress string) (TransportChannel, error) {
	addr, err := net.ResolveUDPAddr(Net, ServerAddress)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP(Net, addr)
	if err != nil {
		return nil, err
	}
	u := &udpChannel{
		c:            c,
		sendQueue:    make(chan *udpPacketData),
		receiveQueue: make(chan *udpPacketData),
	}
	return u, nil
}

func (u *udpChannel) Close() error {
	return u.c.Close()
}

func (u *udpChannel) udpReadWorker() {
	for {
		pkt := make([]byte, 1800)
		n, addr, err := u.c.ReadFromUDP(pkt)
		if err != nil {
			return
		}
		pkt = pkt[:n]
		u.receiveQueue <- &udpPacketData{p: pkt, a: addr}
	}
}
func (u *udpChannel) udpWriteWorker() {
	for p, ok := <-u.sendQueue; ok; p, ok = <-u.sendQueue {
		_, err := u.c.WriteToUDP(p.p, p.a)
		if err != nil {
			return
		}
	}
}

func (u *udpChannel) SendPacket(pkt []byte, client TransportChannelClientID) {
	addr, ok := client.(net.UDPAddr)
	if !ok {
		return
	}
	u.sendQueue <- &udpPacketData{p: pkt, a: &addr}
}

func (u *udpChannel) ReceivePacket() ([]byte, TransportChannelClientID) {
	d, ok := <-u.receiveQueue
	if !ok {
		return nil, nil
	}
	return d.p, *d.a
}
