package transport

// 20 bytes is enough for ipv6 + port
type TransportChannelClientID interface{}

type TransportChannel interface {
	RegisterOnClientDisconnect(<-chan *TransportChannelClientID)
	SendPacket(pkt []byte, client *TransportChannelClientID)
	ReceivePacket() ([]byte, *TransportChannelClientID)
}
