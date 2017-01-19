package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"sync"

	"github.com/teambition/gear-auth/pbkdf2"
)

const cipherFlag = "^$"

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

// AESKey return a key to encrypt or decrypt data.
func (c *Crypto) AESKey(a, b string) string {
	buf := c.hmacSum(string(c.hmacSum(a)) + b)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// EncryptUserPass ...
func (c *Crypto) EncryptUserPass(id, pass string) string {
	iv := RandBytes(16)
	b := c.encryptUserPass(iv, append(c.hmacSum(id), []byte(pass)...))
	return base64.RawURLEncoding.EncodeToString(b)
}

func (c *Crypto) encryptUserPass(iv, pass []byte) []byte {
	b := pbkdf2.Key(pass, c.salt, 1025, 32, func() hash.Hash {
		return hmac.New(sha256.New, iv)
	})
	return append(b, iv...)
}

// ValidateUserPass validate user' id and password with a password in database
func (c *Crypto) ValidateUserPass(id, pass, dbpass string) bool {
	a, err := base64.RawURLEncoding.DecodeString(dbpass)
	if err != nil {
		return false
	}
	b := c.encryptUserPass(a[32:], append(c.hmacSum(id), []byte(pass)...))
	return subtle.ConstantTimeCompare(a, b) == 1
}

// EncryptData encrypt data with key
func (c *Crypto) EncryptData(key, plainData string) (string, error) {
	block, err := aes.NewCipher(c.hmacSum(key))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()

	plainData = cipherFlag + plainData
	cipherData := make([]byte, blockSize+len(plainData))
	iv := cipherData[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherData[blockSize:], []byte(plainData))
	return base64.RawURLEncoding.EncodeToString(cipherData), nil
}

// DecryptData decrypt data with key
func (c *Crypto) DecryptData(key, cipherData string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(cipherData)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.hmacSum(key))
	if err != nil {
		return "", err
	}
	blockSize := block.BlockSize()
	iv := data[:blockSize]

	plainData := make([]byte, len(data)-blockSize)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plainData, data[blockSize:])
	val := string(plainData)
	if val[0:2] != cipherFlag {
		return "", errors.New("invalid data")
	}
	return val[2:], nil
}

func (c *Crypto) hmacSum(str string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hash.Reset()
	c.hash.Write([]byte(str))
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
