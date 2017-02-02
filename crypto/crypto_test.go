package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCrypto(t *testing.T) {
	c := New([]byte("KPass"))

	t.Run("AESKey", func(t *testing.T) {
		assert := assert.New(t)

		k := c.AESKey("admin", "test pass")
		b, _ := base64.RawURLEncoding.DecodeString(k)
		assert.True(len(b) == 32)
	})

	t.Run("SignPass and VerifyPass", func(t *testing.T) {
		assert := assert.New(t)

		epass := c.SignPass("admin", "test pass")
		assert.True(c.VerifyPass("admin", "test pass", epass))
		assert.False(c.VerifyPass("admin1", "test pass", epass))
		assert.False(c.VerifyPass("admin", "test pass1", epass))
		assert.False(c.VerifyPass("admin", "test pass", epass[1:]))
	})

	t.Run("EncryptText and DecryptText", func(t *testing.T) {
		assert := assert.New(t)

		key := c.AESKey("admin", "test pass")

		edata, err := c.EncryptText(key, "Hello! 中国")
		assert.Nil(err)
		data, err := c.DecryptText(key, edata)
		assert.Nil(err)
		assert.Equal("Hello! 中国", data)

		edata, err = c.EncryptText(key, "")
		assert.Nil(err)
		data, err = c.DecryptText(key, edata)
		assert.Nil(err)
		assert.Equal("", data)

		data, err = c.DecryptText(key, edata+"1")
		assert.NotNil(err)
		assert.Equal("", data)

		data, err = c.DecryptText(key, edata[:len(edata)-10])
		assert.NotNil(err)
		assert.Equal("", data)
	})
}
