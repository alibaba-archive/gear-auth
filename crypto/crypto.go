package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"io"

	"github.com/teambition/gear-auth/pbkdf2"
)

// Crypto contains some useful methods.
type Crypto struct {
	salt []byte
}

// New returns a Crypto instance.
func New(salt []byte) *Crypto {
	return &Crypto{salt: salt}
}

// AESKey returns a string key to encrypt or decrypt text.
func (c *Crypto) AESKey(a, b string) (key string) {
	buf := c.hmacSum(append(c.hmacSum([]byte(a)), []byte(b)...))
	return base64.RawURLEncoding.EncodeToString(buf)
}

// SignPass returns a string checkPass by the user' name and pass.
func (c *Crypto) SignPass(name, pass string) (checkPass string) {
	iv := RandBytes(8)
	b := c.signPass(iv, append(c.hmacSum([]byte(name)), []byte(pass)...))
	return base64.RawURLEncoding.EncodeToString(b)
}

func (c *Crypto) signPass(iv, pass []byte) []byte {
	b := pbkdf2.Key(pass, c.salt, 1025, 32, func() hash.Hash {
		return hmac.New(sha256.New, iv)
	})
	return append(b, iv...)
}

// VerifyPass verify user' name and password with a checkPass(stored in database)
func (c *Crypto) VerifyPass(name, pass, checkPass string) bool {
	a, err := base64.RawURLEncoding.DecodeString(checkPass)
	if err != nil {
		return false
	}
	b := c.signPass(a[32:], append(c.hmacSum([]byte(name)), []byte(pass)...))
	return subtle.ConstantTimeCompare(a, b) == 1
}

// EncryptText encrypt data with key
func (c *Crypto) EncryptText(key, plainText string) (string, error) {
	k := c.hmacSum([]byte(key))
	size := aes.BlockSize
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	data := []byte(plainText)
	cipherData := make([]byte, size+len(data))
	iv := cipherData[:size]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherData[size:], data)
	h := hmac.New(sha1.New, cipherData)
	h.Write(data)
	return base64.RawURLEncoding.EncodeToString(append(cipherData, h.Sum(nil)...)), nil
}

// DecryptText decrypt data with key
func (c *Crypto) DecryptText(key, cipherText string) (string, error) {
	cipherData, err := base64.RawURLEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	size := aes.BlockSize
	if len(cipherData) < size+sha1.Size {
		return "", errors.New("invalid data")
	}

	k := c.hmacSum([]byte(key))
	checkSum := cipherData[len(cipherData)-sha1.Size:]
	cipherData = cipherData[:len(cipherData)-sha1.Size]
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	data := make([]byte, len(cipherData)-size)
	stream := cipher.NewCTR(block, cipherData[:size])
	stream.XORKeyStream(data, cipherData[size:])

	h := hmac.New(sha1.New, cipherData)
	h.Write(data)
	if subtle.ConstantTimeCompare(h.Sum(nil), checkSum) != 1 {
		return "", errors.New("invalid data")
	}
	return string(data), nil
}

func (c *Crypto) hmacSum(data []byte) []byte {
	h := hmac.New(sha256.New, c.salt)
	h.Write(data)
	return h.Sum(nil)
}

// RandBytes return rand bytes
func RandBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
