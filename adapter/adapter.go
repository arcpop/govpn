package adapter

import (
	"github.com/arcpop/govpn/core"
)

type Instance interface {
	Close() error
	GetName() string
	ReceiveChannel() <-chan []byte
	TransmitChannel() chan<- []byte
	GetMTU() int
	GetMACAddress() *core.MacAddr
}

func NewTAP(name string, mtu int) (Instance, error) {
	return newTAP(name, mtu)
}
