package transport

import (
	"net"
)

type pktData struct {
}

type udpChannel struct {
	c            *net.UDPConn
	sendQueue    chan *pktData
	receiveQueue chan *pktData
}

func NewUDP(Net, ServerAddress string) (Channel, error) {
	addr, err := net.ResolveUDPAddr(Net, ServerAddress)
	if err != nil {
		return nil, err
	}

}
