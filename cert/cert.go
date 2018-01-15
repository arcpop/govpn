package cert

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"
)

type CertificateAndKey struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
}

func ParseCertificate(certFile string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	var certData []byte
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEM = pem.Decode(certPEM)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			certData = certDERBlock.Bytes
			break
		}
	}
	if certData == nil {
		return nil, errors.New("core: certificate not found in file " + certFile)
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func ParseKey(keyFile string) (crypto.Signer, error) {
	keyPEM, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	var keyData []byte
	for {
		var keyDERBlock *pem.Block
		keyDERBlock, keyPEM = pem.Decode(keyPEM)
		if keyDERBlock == nil {
			break
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			keyData = keyDERBlock.Bytes
			break
		}
	}
	if keyData == nil {
		return nil, errors.New("core: key not found in file " + keyFile)
	}
	key, err := x509.ParseECPrivateKey(keyData)
	if err != nil {
		return nil, err
	}
	return key, nil
}
