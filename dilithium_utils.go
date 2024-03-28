package jwt

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium"
)

var (
	ErrNotDilithiumPublicKey  = errors.New("key is not a valid Dilithium public key")
	ErrNotDilithiumPrivateKey = errors.New("key is not a valid Dilithium private key")

	oidPublicKeyDilithium2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 4, 4}
	oidPublicKeyDilithium3 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 6, 5}
	oidPublicKeyDilithium5 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7}
)

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// ParseDilithiumPrivateKeyFromPEM parses a PEM encoded Dilithium Private Key Structure
func ParseDilithiumPrivateKeyFromPEM(key []byte) (dilithium.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	var privKey pkcs8
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, err
	}
	if parsedKey, err = parsePrivate(&privKey); err != nil {
		return nil, err
	}

	var pkey dilithium.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(dilithium.PrivateKey); !ok {
		return nil, ErrNotDilithiumPrivateKey
	}

	return pkey, nil
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// ParseDilithiumPublicKeyFromPEM parses a PEM encoded PKCS8 public key
func ParseDilithiumPublicKeyFromPEM(key []byte) (dilithium.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(block.Bytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	if parsedKey, err = parsePublicKey(&pki); err != nil {
		return nil, err
	}

	var pkey dilithium.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(dilithium.PublicKey); !ok {
		return nil, ErrNotDilithiumPublicKey
	}

	return pkey, err
}

func parsePrivate(privKey *pkcs8) (any, error) {
	oid := privKey.Algo.Algorithm

	var mode dilithium.Mode
	switch {
	case oid.Equal(oidPublicKeyDilithium2):
		mode = dilithium.Mode2
	case oid.Equal(oidPublicKeyDilithium3):
		mode = dilithium.Mode3
	case oid.Equal(oidPublicKeyDilithium5):
		mode = dilithium.Mode5
	default:
		return nil, errors.New("x509: unknown public key algorithm")
	}

	if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
		return nil, errors.New("x509: invalid Dilithium private key parameters")
	}
	privateKey := privKey.PrivateKey[:mode.PrivateKeySize()]
	publicKey := privKey.PrivateKey[mode.PrivateKeySize():]
	if l := len(publicKey); l != mode.PublicKeySize() {
		return nil, fmt.Errorf("x509: invalid Dilithium private key length: %d", l)
	}

	return mode.PrivateKeyFromBytes(privateKey), nil
}

func parsePublicKey(keyData *publicKeyInfo) (any, error) {
	oid := keyData.Algorithm.Algorithm
	params := keyData.Algorithm.Parameters
	der := keyData.PublicKey.RightAlign()

	var mode dilithium.Mode
	switch {
	case oid.Equal(oidPublicKeyDilithium2):
		mode = dilithium.Mode2
	case oid.Equal(oidPublicKeyDilithium3):
		mode = dilithium.Mode3
	case oid.Equal(oidPublicKeyDilithium5):
		mode = dilithium.Mode5
	default:
		return nil, errors.New("x509: unknown public key algorithm")
	}

	if len(params.FullBytes) != 0 {
		return nil, errors.New("x509: Dilithium key encoded with illegal parameters")
	}
	if len(der) != mode.PublicKeySize() {
		return nil, errors.New("x509: wrong Dilithium3 public key size")
	}

	return mode.PublicKeyFromBytes(der), nil
}
