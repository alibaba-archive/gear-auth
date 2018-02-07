package ed25519

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"

	joseCrypto "github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	authJwt "github.com/teambition/gear-auth/jwt"
	ED25519 "golang.org/x/crypto/ed25519"
)

// ErrED25519Verification is missing from crypto/ed25519 compared to crypto/rsa
var ErrED25519Verification = errors.New("crypto/ed25519: verification error")

type signingMethodED25519 struct {
	Name string
	Hash crypto.Hash
}

// Specific instances of EC SigningMethods.
var (
	// SigningMethodES256 implements ED25519.
	SigningMethodED25519 = &signingMethodED25519{
		Name: "ED25519",
		Hash: crypto.SHA512, // not used
	}
)

func init() {
	jws.RegisterSigningMethod(SigningMethodED25519)
}

// GenerateKey generates a public/private key pair using entropy from rand.
// the keys is encoded by base64.RawURLEncoding
func GenerateKey() (publicKey, privateKey string) {
	public, private, err := ED25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(public), base64.RawURLEncoding.EncodeToString(private)
}

// KeyPairFrom converts key encoded by base64.RawURLEncoding to KeyPair.
// privateKey is used for sign, publicKey is used for verify.
// if privateKey omits, sign method can't be used.
func KeyPairFrom(publicKey string, privateKey ...string) (authJwt.KeyPair, error) {
	keyPair := authJwt.KeyPair{}
	public, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return keyPair, err
	}
	if l := len(public); l != ED25519.PublicKeySize {
		return keyPair, errors.New("ed25519: bad public key length: " + strconv.Itoa(l))
	}
	keyPair.PublicKey = ED25519.PublicKey(public)

	if len(privateKey) > 0 {
		private, err := base64.RawURLEncoding.DecodeString(privateKey[0])
		if err != nil {
			return keyPair, err
		}
		if l := len(private); l != ED25519.PrivateKeySize {
			return keyPair, errors.New("ed25519: bad private key length: " + strconv.Itoa(l))
		}
		if !bytes.Equal(ED25519.PrivateKey(private).Public().(ED25519.PublicKey), public) {
			return keyPair, errors.New("ed25519: bad public/private key pair")
		}
		keyPair.PrivateKey = ED25519.PrivateKey(private)
	}
	return keyPair, nil
}

// Alg returns the name of the SigningMethodED25519 instance.
func (m *signingMethodED25519) Alg() string { return m.Name }

// Verify implements the Verify method from SigningMethod.
// For this verify method, key must be an *ecdsa.PublicKey.
func (m *signingMethodED25519) Verify(data []byte, signature joseCrypto.Signature, key interface{}) error {
	publicKey, ok := key.(ED25519.PublicKey)
	if !ok {
		return joseCrypto.ErrInvalidKey
	}

	// Verify the signature
	if !ED25519.Verify(publicKey, data, signature) {
		return ErrED25519Verification
	}
	return nil
}

// Sign implements the Sign method from SigningMethod.
// For this signing method, key must be an *ecdsa.PrivateKey.
func (m *signingMethodED25519) Sign(data []byte, key interface{}) (joseCrypto.Signature, error) {
	privateKey, ok := key.(ED25519.PrivateKey)
	if !ok {
		return nil, joseCrypto.ErrInvalidKey
	}

	return joseCrypto.Signature(ED25519.Sign(privateKey, data)), nil
}

// Hasher implements the Hasher method from SigningMethod.
func (m *signingMethodED25519) Hasher() crypto.Hash {
	return m.Hash
}

// MarshalJSON is in case somebody decides to place SigningMethodED25519
// inside the Header, presumably because they (wrongly) decided it was a good
// idea to use the SigningMethod itself instead of the SigningMethod's Alg
// method. In order to keep things sane, marshalling this will simply
// return the JSON-compatible representation of m.Alg().
func (m *signingMethodED25519) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.Alg() + `"`), nil
}

var _ json.Marshaler = (*signingMethodED25519)(nil)
