package crypto

import (
	"encoding/base64"
	"fmt"
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

	t.Run("EncryptUserPass and ValidateUserPass", func(t *testing.T) {
		assert := assert.New(t)

		epass := c.EncryptUserPass("admin", "test pass")
		assert.True(c.ValidateUserPass("admin", "test pass", epass))
		assert.False(c.ValidateUserPass("admin1", "test pass", epass))
		assert.False(c.ValidateUserPass("admin", "test pass1", epass))
		assert.False(c.ValidateUserPass("admin", "test pass", epass[1:]))
	})

	t.Run("EncryptData and DecryptData", func(t *testing.T) {
		assert := assert.New(t)

		key := c.AESKey("admin", "test pass")

		edata, err := c.EncryptData(key, "Hello! 中国")
		assert.Nil(err)
		data, err := c.DecryptData(key, edata)
		assert.Nil(err)
		assert.Equal("Hello! 中国", data)

		// fmt.Println(edata)
		data, err = c.DecryptData(key, edata[1:])
		fmt.Println(err, data)
		assert.NotNil(err)
	})
}
