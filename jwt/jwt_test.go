package jwt

import (
	"testing"
	"time"

	joseCrypto "github.com/SermoDigital/jose/crypto"
	josejws "github.com/SermoDigital/jose/jws"
	josejwt "github.com/SermoDigital/jose/jwt"
	"github.com/stretchr/testify/assert"
)

func TestJWT(t *testing.T) {
	t.Run("New without key", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New()
		assert.Equal(1, len(jwter.keys))
		assert.Equal(joseCrypto.Unsecured, jwter.method)

		token, err := jwter.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.True(claims.Has("iat"))
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("New with a key", func(t *testing.T) {
		assert := assert.New(t)

		jwter0 := New()
		jwter1 := New([]byte("key1"))
		jwter2 := New(StrToKeys("key2")...)
		assert.Equal(1, len(jwter1.keys))
		assert.Equal(joseCrypto.SigningMethodHS256, jwter1.method)

		token, err := jwter1.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter1.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		_, err = jwter0.Verify(token)
		assert.NotNil(err)
		_, err = jwter2.Verify(token)
		assert.NotNil(err)

		token, err = jwter0.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)
		_, err = jwter1.Verify(token)
		assert.NotNil(err)

		jwtToken, _ := josejws.ParseJWT([]byte(token))
		_, err = Verify(jwtToken, joseCrypto.SigningMethodHS256, []interface{}{[]byte("key1")})
		assert.NotNil(err)
	})

	t.Run("New with more key", func(t *testing.T) {
		assert := assert.New(t)

		jwter1 := New([]byte("key1"))
		jwter2 := New([]byte("key2"), []byte("key1"))
		assert.Equal(1, len(jwter1.keys))
		assert.Equal(2, len(jwter2.keys))

		token, err := jwter1.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter2.Verify(token)
		assert.Equal("OK", claims.Get("test"))

		token, err = jwter2.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)
		_, err = jwter1.Verify(token)
		assert.NotNil(err)
	})

	t.Run("Sign with map[string]interface{}", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		token, err := jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))

		jwtToken, _ := josejws.ParseJWT([]byte(token))
		claims, _ = Verify(jwtToken, joseCrypto.SigningMethodHS256, []interface{}{[]byte("key1")})
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("Sign with josejws.Claims", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		token, err := jwter.Sign(josejws.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))

		jwtToken, _ := josejws.ParseJWT([]byte(token))
		claims, _ = Verify(jwtToken, joseCrypto.SigningMethodHS256, []interface{}{[]byte("key1")})
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("Sign with custom expiresIn", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		assert.Equal(time.Duration(0), jwter.GetExpiresIn())
		jwter.SetExpiresIn(time.Minute)
		assert.Equal(time.Minute, jwter.GetExpiresIn())

		token, err := jwter.Sign(josejws.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		time1, _ := claims.Expiration()
		assert.True(time1.Unix() > time.Now().Unix())

		token2, _ := jwter.Sign(josejws.Claims{"test": "OK"}, time.Duration(0))
		claims2, _ := jwter.Verify(token2)
		time2, _ := claims2.Expiration()
		assert.True(time2.IsZero())

		token3, _ := jwter.Sign(josejws.Claims{"test": "OK"}, time.Second)
		claims3, _ := jwter.Verify(token3)
		time3, _ := claims3.Expiration()
		assert.True(time1.Unix() > time3.Unix())
	})

	t.Run("Decode", func(t *testing.T) {
		assert := assert.New(t)

		jwter1 := New([]byte("key1"))
		jwter2 := New([]byte("key2"))
		token, err := jwter1.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)

		claims, _ := jwter1.Decode(token)
		assert.Equal("OK", claims.Get("test"))
		claims, _ = jwter2.Decode(token)
		assert.Equal("OK", claims.Get("test"))

		_, err = jwter2.Decode(token[1:])
		assert.NotNil(err)
	})

	t.Run("SetIssuer", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		token, err := jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		assert.Nil(claims.Get("iss"))

		jwter.SetIssuer("Gear")
		token, err = jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, _ = jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		assert.Equal("Gear", claims.Get("iss"))
	})

	t.Run("SetAudience", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		token, err := jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		assert.Nil(claims.Get("iss"))

		jwter.SetAudience("Gear")
		token, err = jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, _ = jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		assert.Equal("Gear", claims.Get("aud"))
	})

	t.Run("SetExpiresIn", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		token, err := jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		assert.Nil(claims.Get("exp"))

		jwter.SetExpiresIn(time.Second)
		token, err = jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, err = jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		assert.True(claims.Get("exp").(float64) > 0)

		time.Sleep(1200 * time.Millisecond)
		claims, err = jwter.Verify(token)
		assert.Nil(claims)
		assert.NotNil(err)
	})

	t.Run("SetKeys", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		assert.Panics(func() {
			jwter.SetKeys(nil)
		})
		jwter.SetKeys([]byte("key2"))
		token, err := jwter.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("SetMethods", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		assert.Panics(func() {
			jwter.SetMethods(nil)
		})
		jwter.SetMethods(joseCrypto.SigningMethodHS384)
		token, err := jwter.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("SetValidator", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]byte("key1"))
		assert.Panics(func() {
			var v *josejwt.Validator
			jwter.SetValidator(v)
		})

		validator := &josejwt.Validator{}
		validator.SetSubject("test")
		jwter.SetValidator(validator)

		token, err := jwter.Sign(josejwt.Claims{"test": "OK"})
		assert.Nil(err)
		_, err = jwter.Verify(token)
		assert.NotNil(err)

		token, _ = jwter.Sign(josejwt.Claims{"test": "OK", "sub": "test"})
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		sub, _ := claims.Subject()
		assert.Equal("test", sub)
	})

	t.Run("support SigningMethodRS256", func(t *testing.T) {
		assert := assert.New(t)
		// 512 bit, PKCS#8
		privateKey, _ := joseCrypto.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAwNcqwbtB4MZyNI27
+u/wPJ7t72lp5EBsu5aJWFCEUu98o4kforWRkPP1LLc8oL03co7Wglin2/EM2xn6
/8VSnwIDAQABAkEAj+R+DQ0zfQvW0AwqhnZfZnyYwpp/30eLWvZbCcEa2954Ehwl
YQ7b1fiBEbWmNu/9C+5s2Q02YbxtgWGhJ5uxQQIhAOMdNjRI+ijYaGLl3peFcCYq
snWrm9Q6tg0IE0jfdXOvAiEA2V4DeexvcfN1KQre7WNNNtOFmXktlzahyVcBB12m
nBECIQC0xx3MRIKLXKbKgfrKVTbNypK+w1iIeCtM+C6RhP1ylQIgGqxIrOtweYEw
fUrSNDsdPH8UQ9L03zta+wPsImVBjqECIHiRnbty/YtVop43mMpH874DJfaYlxs5
UwLZRrXB/rC5
-----END PRIVATE KEY-----`))

		publicKey, _ := joseCrypto.ParseRSAPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMDXKsG7QeDGcjSNu/rv8Dye7e9paeRA
bLuWiVhQhFLvfKOJH6K1kZDz9Sy3PKC9N3KO1oJYp9vxDNsZ+v/FUp8CAwEAAQ==
-----END PUBLIC KEY-----`))

		jwter := New(KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		})
		jwter.SetMethods(joseCrypto.SigningMethodRS256)
		token, err := jwter.Sign(josejws.Claims{"test": "OK"})
		// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiT0sifQ.mhv0HslKGE3j5w-1jQLAr_jNBXeaIObaJw5Nn9KpaM5pcv9PmXiBG_9S7-a2I4lO_dZtI__b6Y5Ym2z7kP4z5Q
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))

		jwtToken, _ := josejws.ParseJWT([]byte(token))
		claims, _ = Verify(jwtToken, joseCrypto.SigningMethodRS256, []interface{}{KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}})
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("support SigningMethodPS256", func(t *testing.T) {
		assert := assert.New(t)
		// 512 bit, PKCS#8
		privateKey, _ := joseCrypto.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAwNcqwbtB4MZyNI27
+u/wPJ7t72lp5EBsu5aJWFCEUu98o4kforWRkPP1LLc8oL03co7Wglin2/EM2xn6
/8VSnwIDAQABAkEAj+R+DQ0zfQvW0AwqhnZfZnyYwpp/30eLWvZbCcEa2954Ehwl
YQ7b1fiBEbWmNu/9C+5s2Q02YbxtgWGhJ5uxQQIhAOMdNjRI+ijYaGLl3peFcCYq
snWrm9Q6tg0IE0jfdXOvAiEA2V4DeexvcfN1KQre7WNNNtOFmXktlzahyVcBB12m
nBECIQC0xx3MRIKLXKbKgfrKVTbNypK+w1iIeCtM+C6RhP1ylQIgGqxIrOtweYEw
fUrSNDsdPH8UQ9L03zta+wPsImVBjqECIHiRnbty/YtVop43mMpH874DJfaYlxs5
UwLZRrXB/rC5
-----END PRIVATE KEY-----`))

		publicKey, _ := joseCrypto.ParseRSAPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMDXKsG7QeDGcjSNu/rv8Dye7e9paeRA
bLuWiVhQhFLvfKOJH6K1kZDz9Sy3PKC9N3KO1oJYp9vxDNsZ+v/FUp8CAwEAAQ==
-----END PUBLIC KEY-----`))

		jwter := New(KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		})
		jwter.SetMethods(joseCrypto.SigningMethodPS256)
		token, err := jwter.Sign(josejws.Claims{"test": "OK"})
		// eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiT0sifQ.J9q3dZLqacdQp_PdqVHfaNNVYUgFyxbV8jhX8HnoZUiHlZKGUXmVDcSSJ4ZfpMUcLmXUDlq5nee9ad0w2IU9DA
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))

		jwtToken, _ := josejws.ParseJWT([]byte(token))
		claims, _ = Verify(jwtToken, joseCrypto.SigningMethodPS256, []interface{}{KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}})
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("support SigningMethodES256", func(t *testing.T) {
		assert := assert.New(t)
		// 512 bit, PKCS#8
		privateKey, _ := joseCrypto.ParseECPrivateKeyFromPEM([]byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAh5qA3rmqQQuu0vbKV/+zouz/y/Iy2pLpIcWUSyImSwoAoGCCqGSM49
AwEHoUQDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpM
cT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END EC PRIVATE KEY-----`))

		publicKey, _ := joseCrypto.ParseECPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYD54V/vp+54P9DXarYqx4MPcm+HK
RIQzNasYSoRQHQ/6S6Ps8tpMcT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END PUBLIC KEY-----`))

		jwter := New(KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		})
		jwter.SetMethods(joseCrypto.SigningMethodES256)
		token, err := jwter.Sign(josejws.Claims{"test": "OK"})
		// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiT0sifQ.MEQCIAy5-edjjRliSD4rgYTL02nuNka_n_tGUzDLEvHAKUcpAiAu3QkiPvB3sYO5ZAYJWCPdCk7lh4yYSy4z7VorZ893cQ
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))

		jwtToken, _ := josejws.ParseJWT([]byte(token))
		claims, _ = Verify(jwtToken, joseCrypto.SigningMethodES256, []interface{}{KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}})
		assert.Equal("OK", claims.Get("test"))
	})
}
