package adapter

import (
	"errors"

	"github.com/arcpop/govpn/core"
)

var (
	ErrInvalidMTU = errors.New("adapter: invalid mtu")
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
	if mtu <= 0 {
		return nil, ErrInvalidMTU
	}
	return newTAP(name, mtu)
}
