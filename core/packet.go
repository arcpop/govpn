package core

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidClientHello = errors.New("core: invalid ClientHello packet")
	ErrInvalidServerHello = errors.New("core: invalid ServerHello packet")
	ErrInvalidCertificate = errors.New("core: unsupported certificate")
	ErrInvalidSignature   = errors.New("core: invalid signature")
	ErrInvalidVPNPacket   = errors.New("core: invalid vpn packet")
	ErrInvalidAEAD        = errors.New("core: invalid aead specified")
)

var (
	GoVPNAEADData = []byte("govpn-aead-data")
)

type ClientHelloData struct {
	Type                    PacketType
	CurveSelection          CurveType
	AEADSelection           AEADType
	ClientSessionKeyLength  int //sent as LittleEndian uint16
	ClientCertificateLength int //sent as LittleEndian uint16
	ClientSessionKey        []byte
	ClientCertificate       *x509.Certificate //returned for server
	Signature               []byte            //not used in code
}

const ClientHelloDataLength = 7

type ServerHelloData struct {
	Type                   PacketType
	SessionNonce           [5]byte
	ServerSessionKeyLength int
	ServerSessionKey       DHPubKey
	Signature              []byte
}

const ServerHelloDataLength = 8

type VpnPacket struct {
	Type          PacketType
	Nonce         [6]byte
	PayloadLength uint16
	Payload       []byte
}

const VPNPacketLength = 9

type SymmetricCryptoContext struct {
	SymmetricCipher AEADType
	SessionNonce    [5]byte
	SharedSecret    []byte
	NonceCounter    uint64
}

func createAEADInstance(ctx *SymmetricCryptoContext) (cipher.AEAD, error) {
	switch ctx.SymmetricCipher {
	case Aes128Gcm:
		a, err := aes.NewCipher(ctx.SharedSecret)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(a)
	case Aes256Gcm:
		a, err := aes.NewCipher(ctx.SharedSecret)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(a)

	case Chacha20Poly1305:
		return chacha20poly1305.New(ctx.SharedSecret)
	}
	return nil, ErrInvalidAEAD
}

func encryptVPNPacket(p []byte, ctx *SymmetricCryptoContext, clientToServer bool) ([]byte, error) {
	n := atomic.AddUint64(&ctx.NonceCounter, 1)
	if n > 0xFFFFFFFFFFFF {
		log.Println("core: nonce overflow")
		atomic.StoreUint64(&ctx.NonceCounter, 0)
		n = 0
	}
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[0:8], n)
	if clientToServer {
		nonce[6] = 0xAE
	} else {
		nonce[6] = 0xEA
	}
	copy(nonce[7:12], ctx.SessionNonce[:])

	c, err := createAEADInstance(ctx)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, VPNPacketLength, VPNPacketLength+len(p)+c.Overhead())
	buf[0] = byte(VpnPacketType)
	copy(buf[1:7], nonce[0:6])
	buf = c.Seal(buf, nonce[:], p[:], GoVPNAEADData)
	binary.LittleEndian.PutUint16(buf[7:9], uint16(len(buf)-VPNPacketLength))
	return buf, nil
}

func decryptVPNPacket(p []byte, ctx *SymmetricCryptoContext, clientToServer bool) ([]byte, error) {
	if len(p) < VPNPacketLength {
		return nil, ErrInvalidVPNPacket
	}
	if PacketType(p[0]) != VpnPacketType {
		return nil, ErrInvalidVPNPacket
	}
	var nonce [12]byte

	copy(nonce[0:6], p[1:7])
	if clientToServer {
		nonce[6] = 0xAE
	} else {
		nonce[6] = 0xEA
	}
	copy(nonce[7:12], ctx.SessionNonce[:])

	c, err := createAEADInstance(ctx)
	if err != nil {
		return nil, err
	}

	l := binary.LittleEndian.Uint16(p[7:9])
	return c.Open(nil, nonce[:], p[VPNPacketLength:VPNPacketLength+l], GoVPNAEADData)
}

func (s *Server) signAndSerializeServerHello(h *ServerHelloData) ([]byte, error) {
	rand.Read(h.SessionNonce[:])
	h.ServerSessionKeyLength = len(h.ServerSessionKey)
	buf := make([]byte, ServerHelloDataLength+h.ServerSessionKeyLength)
	buf[0] = byte(ServerHelloPacketType)
	copy(buf[1:6], h.SessionNonce[:])
	binary.LittleEndian.PutUint16(buf[6:8], uint16(h.ServerSessionKeyLength))

	hasher := sha256.New()
	hasher.Write(buf[0:ServerHelloDataLength])

	hasher.Write(h.ServerSessionKey)
	signature, err := s.serverCertificate.PrivateKey.Sign(rand.Reader, hasher.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	copy(buf[ServerHelloDataLength:], h.ServerSessionKey)
	return append(buf, signature...), nil
}

func (c *Client) deserializeAndVerifyServerHello(p []byte, h *ServerHelloData) (bool, error) {
	if len(p) < ServerHelloDataLength {
		return false, ErrInvalidServerHello
	}

	h.Type = PacketType(p[0])
	copy(h.SessionNonce[:], p[1:6])
	h.ServerSessionKeyLength = int(binary.LittleEndian.Uint16(p[6:8]))

	dataLength := ServerHelloDataLength + h.ServerSessionKeyLength
	if len(p) < dataLength {
		return false, ErrInvalidServerHello
	}

	err := checkSignature(c.serverCertificate, p[0:dataLength], p[dataLength:])
	if err != nil {
		if err == ErrInvalidSignature {
			return false, nil
		}
		return false, err
	}
	h.ServerSessionKey = p[ServerHelloDataLength : ServerHelloDataLength+h.ServerSessionKeyLength]
	return true, nil
}

func (c *Client) signAndSerializeClientHello(h *ClientHelloData, sessionKey DHPubKey) ([]byte, error) {
	h.ClientSessionKeyLength = len(sessionKey)
	h.ClientCertificateLength = len(c.clientCertificate.Certificate.Raw)
	dataLength := ClientHelloDataLength + h.ClientSessionKeyLength + h.ClientCertificateLength
	buf := make([]byte, dataLength)
	buf[0] = byte(ClientHelloPacketType)
	buf[1] = byte(h.CurveSelection)
	buf[2] = byte(h.AEADSelection)
	binary.LittleEndian.PutUint16(buf[3:5], uint16(h.ClientSessionKeyLength))
	binary.LittleEndian.PutUint16(buf[5:7], uint16(h.ClientCertificateLength))
	copy(buf[ClientHelloDataLength:ClientHelloDataLength+h.ClientSessionKeyLength], sessionKey)
	copy(buf[ClientHelloDataLength+h.ClientSessionKeyLength:dataLength], c.clientCertificate.Certificate.Raw)

	hasher := sha256.New()
	hasher.Write(buf)
	digest := hasher.Sum(nil)

	signature, err := c.clientCertificate.PrivateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return append(buf, signature...), nil
}

func (s *Server) deserializeAndVerifyClientHello(p []byte, h *ClientHelloData) (bool, error) {
	if len(p) < ClientHelloDataLength {
		return false, ErrInvalidClientHello
	}
	h.Type = PacketType(p[0])
	h.CurveSelection = CurveType(p[1])
	h.AEADSelection = AEADType(p[2])
	h.ClientSessionKeyLength = int(binary.LittleEndian.Uint16(p[3:5]))
	h.ClientCertificateLength = int(binary.LittleEndian.Uint16(p[5:7]))
	if h.Type != ClientHelloPacketType {
		return false, ErrInvalidClientHello
	}
	dataLength := ClientHelloDataLength + h.ClientCertificateLength + h.ClientSessionKeyLength
	if len(p) < dataLength {
		return false, ErrInvalidClientHello
	}
	certs, err := x509.ParseCertificates(p[ClientHelloDataLength+h.ClientSessionKeyLength : dataLength])
	if err != nil {
		return false, err
	}

	if len(certs) != 1 {
		return false, ErrInvalidCertificate
	}

	if certs[0].PublicKeyAlgorithm != x509.ECDSA {
		log.Println("core: PublicKeyAlgorithm != ECDSA")
		return false, ErrInvalidCertificate
	}

	//VERIFY CERTIFICATE
	err = certs[0].CheckSignatureFrom(s.caCertificate)
	if err != nil {
		log.Println("core: certificate not signed by CA")
		return false, nil
	}
	err = checkSignature(certs[0], p[0:dataLength], p[dataLength:])
	if err != nil {
		if err == ErrInvalidSignature {
			log.Println("core: invalid signature")
			return false, nil
		}
		return false, err
	}
	h.ClientCertificate = certs[0]
	h.ClientSessionKey = p[ClientHelloDataLength : ClientHelloDataLength+h.ClientSessionKeyLength]
	return true, nil
}

type ecdsaSignature struct {
	R, S *big.Int
}

func checkSignature(cert *x509.Certificate, data, signature []byte) error {
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		sig := new(ecdsaSignature)
		rest, err := asn1.Unmarshal(signature, sig)
		if err != nil {
			return err
		}
		if len(rest) > 0 {
			log.Println("core: signature contains trailing bytes, ignoring them")
		}
		if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
			return errors.New("core: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, sig.R, sig.S) {
			return ErrInvalidSignature
		}
		return nil
	default:
		return ErrInvalidCertificate
	}
}
