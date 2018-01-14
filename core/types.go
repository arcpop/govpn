package core

type PacketType byte

const (
	VpnPacketType PacketType = iota
	ClientHelloPacketType
	ServerHelloPacketType
)

type CurveType byte

const (
	Curve25519 CurveType = iota
	P256
	P384
	P521
)

type AEADType byte

const (
	Aes128Gcm AEADType = iota
	Aes256Gcm
	Chacha20Poly1305
)

type DHPubKey []byte

type SharedKey []byte

type MacAddr [6]byte
