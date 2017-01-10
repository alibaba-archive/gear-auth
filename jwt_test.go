package auth

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/mozillazg/request"
	"github.com/stretchr/testify/assert"
	"github.com/teambition/gear"
)

func NewRequst() *request.Request {
	c := &http.Client{}
	return request.NewRequest(c)
}

func TestGearAuthJWT(t *testing.T) {
	t.Run("New without key", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT()
		assert.Equal(1, len(jwter.keys))
		assert.Equal(crypto.Unsecured, jwter.method)

		token, err := jwter.Sign(jwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("New with a key", func(t *testing.T) {
		assert := assert.New(t)

		jwter0 := NewJWT()
		jwter1 := NewJWT([]byte("key1"))
		jwter2 := NewJWT([]byte("key2"))
		assert.Equal(1, len(jwter1.keys))
		assert.Equal(crypto.SigningMethodHS256, jwter1.method)

		token, err := jwter1.Sign(jwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter1.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		_, err = jwter0.Verify(token)
		assert.NotNil(err)
		_, err = jwter2.Verify(token)
		assert.NotNil(err)

		token, err = jwter0.Sign(jwt.Claims{"test": "OK"})
		assert.Nil(err)
		_, err = jwter1.Verify(token)
		assert.NotNil(err)
		assert.Equal(401, err.(*gear.Error).Code)
	})

	t.Run("New with more key", func(t *testing.T) {
		assert := assert.New(t)

		jwter1 := NewJWT([]byte("key1"))
		jwter2 := NewJWT([]byte("key2"), []byte("key1"))
		assert.Equal(1, len(jwter1.keys))
		assert.Equal(2, len(jwter2.keys))

		token, err := jwter1.Sign(jwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter2.Verify(token)
		assert.Equal("OK", claims.Get("test"))

		token, err = jwter2.Sign(jwt.Claims{"test": "OK"})
		assert.Nil(err)
		_, err = jwter1.Verify(token)
		assert.NotNil(err)
		assert.Equal(401, err.(*gear.Error).Code)
	})

	t.Run("Sign with map[string]interface{}", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
		token, err := jwter.Sign(map[string]interface{}{})
		assert.NotNil(err)
		token, err = jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("Sign with jws.Claims", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
		token, err := jwter.Sign(jws.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("Sign with custom expiresIn", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
		assert.Equal(time.Duration(0), jwter.GetExpiresIn())
		jwter.SetExpiresIn(time.Minute)
		assert.Equal(time.Minute, jwter.GetExpiresIn())

		token, err := jwter.Sign(jws.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		time1, _ := claims.Expiration()
		assert.True(time1.Unix() > time.Now().Unix())

		token2, _ := jwter.Sign(jws.Claims{"test": "OK"}, time.Duration(0))
		claims2, _ := jwter.Verify(token2)
		time2, _ := claims2.Expiration()
		assert.True(time2.IsZero())

		token3, _ := jwter.Sign(jws.Claims{"test": "OK"}, time.Second)
		claims3, _ := jwter.Verify(token3)
		time3, _ := claims3.Expiration()
		assert.True(time1.Unix() > time3.Unix())
	})

	t.Run("Decode", func(t *testing.T) {
		assert := assert.New(t)

		jwter1 := NewJWT([]byte("key1"))
		jwter2 := NewJWT([]byte("key2"))
		token, err := jwter1.Sign(jwt.Claims{"test": "OK"})
		assert.Nil(err)

		claims, _ := jwter1.Decode(token)
		assert.Equal("OK", claims.Get("test"))
		claims, _ = jwter2.Decode(token)
		assert.Equal("OK", claims.Get("test"))

		_, err = jwter2.Decode(token[1:])
		assert.NotNil(err)
		assert.Equal(401, err.(*gear.Error).Code)
	})

	t.Run("SetIssuer", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
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

	t.Run("SetExpiresIn", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
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

	t.Run("SetMethods", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
		assert.Panics(func() {
			jwter.SetMethods(nil)
		})
		jwter.SetMethods(crypto.SigningMethodHS384)
		token, err := jwter.Sign(jwt.Claims{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("SetValidator", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
		assert.Panics(func() {
			var v *jwt.Validator
			jwter.SetValidator(v)
		})

		validator := &jwt.Validator{}
		validator.SetSubject("test")
		jwter.SetValidator(validator)

		token, err := jwter.Sign(jwt.Claims{"test": "OK"})
		assert.Nil(err)
		_, err = jwter.Verify(token)
		assert.NotNil(err)

		token, _ = jwter.Sign(jwt.Claims{"test": "OK", "sub": "test"})
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		sub, _ := claims.Subject()
		assert.Equal("test", sub)
	})

	t.Run("should 401", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("my key"))
		app := gear.New()
		app.UseHandler(jwter)
		srv := app.Start()
		defer srv.Close()

		req := NewRequst()
		host := "http://" + srv.Addr().String()

		res, err := req.Get(host)
		assert.Nil(err)
		assert.Equal(401, res.StatusCode)
		body, _ := res.Text()
		assert.Equal("No token found", body)

		jwter1 := NewJWT([]byte("wrong key"))
		claims := jwt.Claims{}
		claims.Set("hello", "world")
		token, _ := jwter1.Sign(claims)
		req.Headers["Authorization"] = "BEARER " + token
		res, err = req.Get(host)
		assert.Nil(err)
		assert.Equal(401, res.StatusCode)
	})

	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("my key 1"), []byte("my key 2"))
		app := gear.New()
		app.Use(jwter.Serve)
		app.Use(func(ctx *gear.Context) error {
			claims, _ := jwter.FromCtx(ctx)
			assert.Equal("world", claims.Get("hello"))
			return ctx.JSON(200, claims)
		})
		srv := app.Start()
		defer srv.Close()

		req := NewRequst()
		host := "http://" + srv.Addr().String()

		claims := jwt.Claims{}
		claims.Set("hello", "world")
		token, _ := jwter.Sign(claims)
		req.Headers["Authorization"] = "BEARER " + token
		res, err := req.Get(host)
		assert.Nil(err)
		assert.Equal(200, res.StatusCode)

		body, _ := ioutil.ReadAll(res.Body)
		assert.Equal(gear.MIMEApplicationJSONCharsetUTF8, res.Header.Get(gear.HeaderContentType))
		assert.True(strings.Contains(string(body), `"hello":"world"`))
		res.Body.Close()

		jwter1 := NewJWT([]byte("my key 2"))
		claims1 := jws.Claims{}
		claims1.Set("hello", "world")
		token, _ = jwter1.Sign(claims1)

		req = NewRequst()
		res, err = req.Get(host + "?access_token=" + token)
		assert.Nil(err)
		assert.Equal(200, res.StatusCode)
		body, _ = ioutil.ReadAll(res.Body)
		assert.Equal(gear.MIMEApplicationJSONCharsetUTF8, res.Header.Get(gear.HeaderContentType))
		assert.True(strings.Contains(string(body), `"hello":"world"`))
		res.Body.Close()
	})

	t.Run("should work with custom TokenExtractor", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("my key 1"))
		jwter.SetTokenParser(func(ctx *gear.Context) string {
			if auth := ctx.Get("Authorization"); strings.HasPrefix(auth, "OAUTH2 ") {
				return auth[7:]
			}
			return ""
		})
		app := gear.New()
		app.Use(func(ctx *gear.Context) error {
			claims, err := jwter.FromCtx(ctx)
			if err != nil {
				assert.Empty(len(claims))
				assert.Nil(claims.Get("hello"))
				return ctx.End(401)
			}
			return ctx.JSON(200, claims)
		})
		srv := app.Start()
		defer srv.Close()

		req := NewRequst()
		host := "http://" + srv.Addr().String()

		claims := jwt.Claims{}
		claims.Set("hello", "world")
		token, _ := jwter.Sign(claims)
		req.Headers["Authorization"] = "OAUTH2 " + token
		res, err := req.Get(host)
		assert.Nil(err)
		assert.Equal(200, res.StatusCode)

		body, _ := ioutil.ReadAll(res.Body)
		assert.Equal(gear.MIMEApplicationJSONCharsetUTF8, res.Header.Get(gear.HeaderContentType))
		assert.True(strings.Contains(string(body), `"hello":"world"`))
		res.Body.Close()

		req = NewRequst()
		res, err = req.Get(host + "?access_token=" + token)
		assert.Nil(err)
		assert.Equal(401, res.StatusCode)
		res.Body.Close()
	})

	t.Run("support SigningMethodRS256", func(t *testing.T) {
		assert := assert.New(t)
		// 512 bit, PKCS#8
		privateKey, _ := crypto.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAwNcqwbtB4MZyNI27
+u/wPJ7t72lp5EBsu5aJWFCEUu98o4kforWRkPP1LLc8oL03co7Wglin2/EM2xn6
/8VSnwIDAQABAkEAj+R+DQ0zfQvW0AwqhnZfZnyYwpp/30eLWvZbCcEa2954Ehwl
YQ7b1fiBEbWmNu/9C+5s2Q02YbxtgWGhJ5uxQQIhAOMdNjRI+ijYaGLl3peFcCYq
snWrm9Q6tg0IE0jfdXOvAiEA2V4DeexvcfN1KQre7WNNNtOFmXktlzahyVcBB12m
nBECIQC0xx3MRIKLXKbKgfrKVTbNypK+w1iIeCtM+C6RhP1ylQIgGqxIrOtweYEw
fUrSNDsdPH8UQ9L03zta+wPsImVBjqECIHiRnbty/YtVop43mMpH874DJfaYlxs5
UwLZRrXB/rC5
-----END PRIVATE KEY-----`))

		publicKey, _ := crypto.ParseRSAPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMDXKsG7QeDGcjSNu/rv8Dye7e9paeRA
bLuWiVhQhFLvfKOJH6K1kZDz9Sy3PKC9N3KO1oJYp9vxDNsZ+v/FUp8CAwEAAQ==
-----END PUBLIC KEY-----`))

		jwter := NewJWT(KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		})
		jwter.SetMethods(crypto.SigningMethodRS256)
		token, err := jwter.Sign(jws.Claims{"test": "OK"})
		// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiT0sifQ.mhv0HslKGE3j5w-1jQLAr_jNBXeaIObaJw5Nn9KpaM5pcv9PmXiBG_9S7-a2I4lO_dZtI__b6Y5Ym2z7kP4z5Q
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("support SigningMethodPS256", func(t *testing.T) {
		assert := assert.New(t)
		// 512 bit, PKCS#8
		privateKey, _ := crypto.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAwNcqwbtB4MZyNI27
+u/wPJ7t72lp5EBsu5aJWFCEUu98o4kforWRkPP1LLc8oL03co7Wglin2/EM2xn6
/8VSnwIDAQABAkEAj+R+DQ0zfQvW0AwqhnZfZnyYwpp/30eLWvZbCcEa2954Ehwl
YQ7b1fiBEbWmNu/9C+5s2Q02YbxtgWGhJ5uxQQIhAOMdNjRI+ijYaGLl3peFcCYq
snWrm9Q6tg0IE0jfdXOvAiEA2V4DeexvcfN1KQre7WNNNtOFmXktlzahyVcBB12m
nBECIQC0xx3MRIKLXKbKgfrKVTbNypK+w1iIeCtM+C6RhP1ylQIgGqxIrOtweYEw
fUrSNDsdPH8UQ9L03zta+wPsImVBjqECIHiRnbty/YtVop43mMpH874DJfaYlxs5
UwLZRrXB/rC5
-----END PRIVATE KEY-----`))

		publicKey, _ := crypto.ParseRSAPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMDXKsG7QeDGcjSNu/rv8Dye7e9paeRA
bLuWiVhQhFLvfKOJH6K1kZDz9Sy3PKC9N3KO1oJYp9vxDNsZ+v/FUp8CAwEAAQ==
-----END PUBLIC KEY-----`))

		jwter := NewJWT(KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		})
		jwter.SetMethods(crypto.SigningMethodPS256)
		token, err := jwter.Sign(jws.Claims{"test": "OK"})
		// eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiT0sifQ.J9q3dZLqacdQp_PdqVHfaNNVYUgFyxbV8jhX8HnoZUiHlZKGUXmVDcSSJ4ZfpMUcLmXUDlq5nee9ad0w2IU9DA
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})

	t.Run("support SigningMethodES256", func(t *testing.T) {
		assert := assert.New(t)
		// 512 bit, PKCS#8
		privateKey, _ := crypto.ParseECPrivateKeyFromPEM([]byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAh5qA3rmqQQuu0vbKV/+zouz/y/Iy2pLpIcWUSyImSwoAoGCCqGSM49
AwEHoUQDQgAEYD54V/vp+54P9DXarYqx4MPcm+HKRIQzNasYSoRQHQ/6S6Ps8tpM
cT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END EC PRIVATE KEY-----`))

		publicKey, _ := crypto.ParseECPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYD54V/vp+54P9DXarYqx4MPcm+HK
RIQzNasYSoRQHQ/6S6Ps8tpMcT+KvIIC8W/e9k0W7Cm72M1P9jU7SLf/vg==
-----END PUBLIC KEY-----`))

		jwter := NewJWT(KeyPair{
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		})
		jwter.SetMethods(crypto.SigningMethodES256)
		token, err := jwter.Sign(jws.Claims{"test": "OK"})
		// eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiT0sifQ.MEQCIAy5-edjjRliSD4rgYTL02nuNka_n_tGUzDLEvHAKUcpAiAu3QkiPvB3sYO5ZAYJWCPdCk7lh4yYSy4z7VorZ893cQ
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
	})
}
