package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/arcpop/govpn/cert"
)

var (
	ErrInvalidCurve = errors.New("invalid curve specified")
)

var (
	CreateCA   bool
	ValidFor   time.Duration
	CurveName  string
	Name       string
	CACertFile string
	CAKeyFile  string
	CertFile   string
	KeyFile    string
)

func main() {
	flag.BoolVar(&CreateCA, "createCA", false, "Create CA keypair")
	flag.DurationVar(&ValidFor, "valid", time.Hour*23*365*10, "The duration of the certificate")
	flag.StringVar(&CurveName, "curve", "P256", "P256, P384 or P521")
	flag.StringVar(&Name, "name", "Test", "The SubjectName field of the certificate")
	flag.StringVar(&CACertFile, "cacert", "ca.pem", "The path to the CA certificate file")
	flag.StringVar(&CAKeyFile, "cakey", "ca.key", "The path to the CA key file")
	flag.StringVar(&CertFile, "cert", "cert.pem", "The path to the certificate file")
	flag.StringVar(&KeyFile, "key", "cert.key", "The path to the key file")
	flag.Parse()

	var c elliptic.Curve
	switch CurveName {
	case "P256":
		c = elliptic.P256()
	case "P384":
		c = elliptic.P384()
	case "P521":
		c = elliptic.P521()
	default:
		log.Println("Invalid curve specified")
		return
	}
	var err error
	var cakey crypto.Signer
	var cacert *x509.Certificate
	if CreateCA {
		cacert, cakey, err = GenerateCAKeypair(c)
	} else {
		cakey, err = cert.ParseKey(CAKeyFile)
		if err != nil {
			log.Fatal(err)
			return
		}
		cacert, err = cert.ParseCertificate(CACertFile)
	}
	if err != nil {
		log.Fatal(err)
		return
	}
	err = CreateCertificate(c, cacert, cakey)
	if err != nil {
		log.Fatal(err)
	}
}

func CreateCertificate(c elliptic.Curve, caCert *x509.Certificate, caKey crypto.Signer) error {
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return err
	}
	pub := priv.Public()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: Name},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(ValidFor),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, pub, caKey)
	if err != nil {
		return err
	}
	certOut, err := os.Create(CertFile)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	keyOut, err := os.Create(KeyFile)
	if err != nil {
		return err
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	pem.Encode(keyOut, block)
	keyOut.Close()
	log.Println("Created keypair for " + Name + " (" + CertFile + " | " + KeyFile + ")")
	return nil
}

func GenerateCAKeypair(c elliptic.Curve) (*x509.Certificate, crypto.Signer, error) {
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "GOVPN-CA"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(ValidFor),
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	certOut, err := os.Create(CACertFile)
	if err != nil {
		return nil, nil, err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	keyOut, err := os.Create(CAKeyFile)
	if err != nil {
		return nil, nil, err
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	pem.Encode(keyOut, block)
	keyOut.Close()
	log.Println("Created CA keypair (" + CACertFile + " | " + CAKeyFile + ")")
	certs, _ := x509.ParseCertificate(certBytes)
	return certs, priv, nil
}
