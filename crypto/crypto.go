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
	"sync"

	"github.com/teambition/gear-auth/pbkdf2"
)

// Crypto contains some useful methods.
type Crypto struct {
	salt []byte
	hash hash.Hash
	mu   sync.Mutex
}

// New returns a Crypto instance.
func New(salt []byte) *Crypto {
	return &Crypto{salt: salt, hash: hmac.New(sha256.New, salt)}
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

	cipherData := make([]byte, size+len(plainText))
	iv := cipherData[:size]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherData[size:], []byte(plainText))
	h := hmac.New(sha1.New, cipherData)
	h.Write(k)
	return base64.RawURLEncoding.EncodeToString(append(cipherData, h.Sum(nil)...)), nil
}

// DecryptText decrypt data with key
func (c *Crypto) DecryptText(key, cipherData string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(cipherData)
	if err != nil {
		return "", err
	}

	size := aes.BlockSize
	if len(data) < size+sha1.Size {
		return "", errors.New("invalid data")
	}

	sum := data[len(data)-sha1.Size:]
	data = data[:len(data)-sha1.Size]
	k := c.hmacSum([]byte(key))
	h := hmac.New(sha1.New, data)
	h.Write(k)
	if subtle.ConstantTimeCompare(h.Sum(nil), sum) != 1 {
		return "", errors.New("invalid data")
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	plainText := make([]byte, len(data)-size)
	stream := cipher.NewCTR(block, data[:size])
	stream.XORKeyStream(plainText, data[size:])
	return string(plainText), nil
}

func (c *Crypto) hmacSum(data []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.hash.Reset()
	c.hash.Write(data)
	return c.hash.Sum(nil)
}

// RandBytes return rand bytes
func RandBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
