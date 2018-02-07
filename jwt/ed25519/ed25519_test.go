package ed25519_test

import (
	"testing"

	josecrypto "github.com/SermoDigital/jose/crypto"
	josejws "github.com/SermoDigital/jose/jws"
	josejwt "github.com/SermoDigital/jose/jwt"
	"github.com/stretchr/testify/assert"

	"github.com/teambition/gear-auth/jwt"
	"github.com/teambition/gear-auth/jwt/ed25519"
)

func TestED25519(t *testing.T) {
	t.Run("support ed25519", func(t *testing.T) {
		assert := assert.New(t)

		publicKey, privateKey := ed25519.GenerateKey()
		keyPair, _ := ed25519.KeyPairFrom(publicKey, privateKey)
		jwter := jwt.New(keyPair)
		jwter.SetMethods(ed25519.SigningMethodED25519)
		token, err := jwter.Sign(josejws.Claims{"test": "OK"})
		// eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJpYXQiOjE1MTgwMTUyMjksInRlc3QiOiJPSyJ9.t0f8dYD6CCf43NrHDr4eSUzatQUN31JKDp6KAm4PBy6kCOHUxYzQUZrhWgSY2uiJ_3ASJyF4EMMrIHGSLIt8Ag
		assert.Nil(err)
		claims, err := jwter.Verify(token)
		assert.Nil(err)
		assert.Equal("OK", claims.Get("test"))

		jwtToken, err := josejws.ParseJWT([]byte(token))

		keyPair2, _ := ed25519.KeyPairFrom(publicKey)
		claims, err = jwt.Verify(jwtToken, ed25519.SigningMethodED25519, []interface{}{keyPair2})
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("support two Signing", func(t *testing.T) {
		assert := assert.New(t)

		jwter1 := jwt.New([]byte("key1"))
		token1, err := jwter1.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)

		jwter2 := jwt.New([]byte("key2"), []byte("key1"))
		token2, err := jwter2.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)

		publicKey3, privateKey3 := ed25519.GenerateKey()
		keyPair3, _ := ed25519.KeyPairFrom(publicKey3, privateKey3)
		jwter3 := jwt.New(keyPair3)
		jwter3.SetMethods(ed25519.SigningMethodED25519)
		token3, err := jwter3.Sign(josejws.Claims{"test": "OK"})
		assert.Nil(err)

		publicKey, privateKey := ed25519.GenerateKey()
		keyPair, _ := ed25519.KeyPairFrom(publicKey, privateKey)
		keyPair2, _ := ed25519.KeyPairFrom(publicKey3)
		jwter := jwt.New()
		jwter.SetSigning(ed25519.SigningMethodED25519, keyPair, keyPair2)
		jwter.SetBackupSigning(josecrypto.SigningMethodHS256, []byte("key2"), []byte("key1"))
		token, err := jwter.Sign(josejws.Claims{"test": "OK"})
		assert.Nil(err)

		claims, err := jwter.Verify(token)
		assert.Nil(err)
		assert.Equal("OK", claims.Get("test"))

		claims, err = jwter.Verify(token1)
		assert.Nil(err)
		assert.Equal("OK", claims.Get("test"))

		claims, err = jwter.Verify(token2)
		assert.Nil(err)
		assert.Equal("OK", claims.Get("test"))

		claims, err = jwter.Verify(token3)
		assert.Nil(err)
		assert.Equal("OK", claims.Get("test"))
	})
}
