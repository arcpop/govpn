package transport

// 20 bytes is enough for ipv6 + port
type TransportChannelClientID interface{}

type TransportChannel interface {
	Close() error
	SendPacket(pkt []byte, client TransportChannelClientID)
	ReceivePacket() ([]byte, TransportChannelClientID)
}
