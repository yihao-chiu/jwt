package jwt

import (
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/sign/dilithium"
)

var (
	ErrDilithiumVerification = errors.New("dilithium: verification error")
)

// SigningMethodDilithium implements the Dilithium family.
// Expects dilithium.PrivateKey for signing and dilithium.PublicKey for verification
type SigningMethodDilithium struct {
	Mode dilithium.Mode
}

// Specific instance for Dilithium
var (
	SigningMethodDilithium2 *SigningMethodDilithium
	SigningMethodDilithium3 *SigningMethodDilithium
	SigningMethodDilithium5 *SigningMethodDilithium
)

func init() {
	SigningMethodDilithium2 = &SigningMethodDilithium{dilithium.Mode2}
	RegisterSigningMethod(SigningMethodDilithium2.Alg(), func() SigningMethod {
		return SigningMethodDilithium2
	})
	SigningMethodDilithium3 = &SigningMethodDilithium{dilithium.Mode3}
	RegisterSigningMethod(SigningMethodDilithium3.Alg(), func() SigningMethod {
		return SigningMethodDilithium3
	})
	SigningMethodDilithium5 = &SigningMethodDilithium{dilithium.Mode5}
	RegisterSigningMethod(SigningMethodDilithium5.Alg(), func() SigningMethod {
		return SigningMethodDilithium5
	})
}

func (m *SigningMethodDilithium) Alg() string {
	return m.Mode.Name()
}

// Verify implements token verification for the SigningMethod.
// For this verify method, key must be an dilithium.PublicKey
func (m *SigningMethodDilithium) Verify(signingString string, sig []byte, key interface{}) error {
	var dilithiumKey dilithium.PublicKey
	var ok bool

	if dilithiumKey, ok = key.(dilithium.PublicKey); !ok {
		return newError("Dilithium verify expects dilithium.PublicKey", ErrInvalidKeyType)
	}

	if len(dilithiumKey.Bytes()) != m.Mode.PublicKeySize() {
		return ErrInvalidKey
	}

	// Verify the signature
	if !m.Mode.Verify(dilithiumKey, []byte(signingString), sig) {
		return ErrDilithiumVerification
	}

	return nil
}

// Sign implements token signing for the SigningMethod.
// For this signing method, key must be an dilithium.PrivateKey
func (m *SigningMethodDilithium) Sign(signingString string, key interface{}) ([]byte, error) {
	var dilithiumKey crypto.Signer
	var ok bool

	if dilithiumKey, ok = key.(crypto.Signer); !ok {
		return nil, newError("Dilithium sign expects crypto.Signer", ErrInvalidKeyType)
	}

	if privateKey, ok := key.(dilithium.PrivateKey); !ok || len(privateKey.Bytes()) != m.Mode.PrivateKeySize() {
		return nil, newError("Dilithium sign expects valid dilithium.PrivateKey", ErrInvalidKeyType)
	}

	if _, ok := dilithiumKey.Public().(dilithium.PublicKey); !ok {
		return nil, ErrInvalidKey
	}

	// Sign the string and return the result. dilithium performs a two-pass hash
	// as part of its algorithm. Therefore, we need to pass a non-prehashed
	// message into the Sign function, as indicated by crypto.Hash(0)
	sig, err := dilithiumKey.Sign(rand.Reader, []byte(signingString), crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	return sig, nil
}
