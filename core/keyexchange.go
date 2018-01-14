package core

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

var (
	ErrInvalidCurve = errors.New("core: invalid curve type")
)

func Curve25519GenerateKey() ([]byte, []byte, error) {
	var private, public [32]byte
	_, err := io.ReadFull(rand.Reader, private[:])
	if err != nil {
		return nil, nil, err
	}

	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	curve25519.ScalarBaseMult(&public, &private)

	return private[:], public[:], nil
}

func Curve25519CalculateSecret(private, theirPublic []byte) ([]byte, error) {
	var secret, priv, pub [32]byte
	copy(priv[:], private[:])
	copy(pub[:], theirPublic)
	curve25519.ScalarMult(&secret, &priv, &pub)

	//Clear copy of private key
	copy(priv[:], make([]byte, 32))
	return secret[:], nil
}

func GenerateKeyPair(t CurveType) ([]byte, []byte, error) {
	if t == Curve25519 {
		return Curve25519GenerateKey()
	}

	var c elliptic.Curve
	switch t {
	case P256:
		c = elliptic.P256()
	case P384:
		c = elliptic.P384()
	case P521:
		c = elliptic.P521()
	default:
		return nil, nil, ErrInvalidCurve
	}

	priv, x, y, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return priv, elliptic.Marshal(c, x, y), nil
}

func CalculateSecret(private, theirPublic []byte, t CurveType) ([]byte, error) {
	if t == Curve25519 {
		return Curve25519CalculateSecret(private, theirPublic)
	}

	var c elliptic.Curve
	switch t {
	case P256:
		c = elliptic.P256()
	case P384:
		c = elliptic.P384()
	case P521:
		c = elliptic.P521()
	default:
		return nil, ErrInvalidCurve
	}
	x, y := elliptic.Unmarshal(c, theirPublic)
	rx, ry := c.ScalarMult(x, y, private)
	secret := elliptic.Marshal(c, rx, ry)
	rx.SetInt64(0)
	ry.SetInt64(0)
	return secret, nil
}
