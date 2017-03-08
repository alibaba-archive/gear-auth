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
	buf := c.HmacSum(append(c.HmacSum([]byte(a)), []byte(b)...))
	return base64.RawURLEncoding.EncodeToString(buf)
}

// SignPass returns a string checkPass by the user' id and pass.
func (c *Crypto) SignPass(id, pass string) (checkPass string) {
	iv := RandBytes(8)
	b := c.signPass(iv, append(c.HmacSum([]byte(id)), []byte(pass)...))
	return base64.RawURLEncoding.EncodeToString(b)
}

func (c *Crypto) signPass(iv, pass []byte) []byte {
	b := pbkdf2.Key(pass, c.salt, 1025, 32, func() hash.Hash {
		return hmac.New(sha256.New, iv)
	})
	return append(b, iv...)
}

// VerifyPass verify user' id and password with a checkPass(stored in database)
func (c *Crypto) VerifyPass(id, pass, checkPass string) bool {
	a, err := base64.RawURLEncoding.DecodeString(checkPass)
	if err != nil {
		return false
	}
	b := c.signPass(a[32:], append(c.HmacSum([]byte(id)), []byte(pass)...))
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Encrypt encrypt data with key
func (c *Crypto) Encrypt(key, data []byte) ([]byte, error) {
	k := c.HmacSum(key)
	size := aes.BlockSize
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	cipherData := make([]byte, size+len(data))
	iv := cipherData[:size]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherData[size:], data)
	h := hmac.New(sha1.New, cipherData)
	h.Write(data)
	return append(cipherData, h.Sum(nil)...), nil
}

// Decrypt decrypt data with key
func (c *Crypto) Decrypt(key, cipherData []byte) ([]byte, error) {
	size := aes.BlockSize
	if len(cipherData) < size+sha1.Size {
		return nil, errors.New("invalid data")
	}

	k := c.HmacSum(key)
	checkSum := cipherData[len(cipherData)-sha1.Size:]
	cipherData = cipherData[:len(cipherData)-sha1.Size]
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(cipherData)-size)
	stream := cipher.NewCTR(block, cipherData[:size])
	stream.XORKeyStream(data, cipherData[size:])

	h := hmac.New(sha1.New, cipherData)
	h.Write(data)
	if subtle.ConstantTimeCompare(h.Sum(nil), checkSum) != 1 {
		return nil, errors.New("invalid data")
	}
	return data, nil
}

// EncryptText encrypt data with key
func (c *Crypto) EncryptText(key, plainText string) (string, error) {
	data, err := c.Encrypt([]byte(key), []byte(plainText))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecryptText decrypt data with key
func (c *Crypto) DecryptText(key, cipherText string) (string, error) {
	cipherData, err := base64.RawURLEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	data, err := c.Decrypt([]byte(key), cipherData)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// HmacSum return hash bytes with salt.
func (c *Crypto) HmacSum(data []byte) []byte {
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
