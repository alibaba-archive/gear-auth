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
		assert.Equal(crypto.Unsecured, jwter.methods[0])

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
		assert.Equal(crypto.SigningMethodHS256, jwter1.methods[0])

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
		token, err := jwter.Sign(map[string]interface{}{"test": "OK"})
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

	t.Run("Sign with custom method", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
		jwter.SetMethods(crypto.SigningMethodHS256, crypto.SigningMethodHS384)
		token, err := jwter.Sign(jws.Claims{"test": "OK"}, crypto.SigningMethodHS384)
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))

		jwter2 := NewJWT([]byte("key1"))
		jwter2.SetMethods(crypto.SigningMethodHS384)
		claims, _ = jwter2.Verify(token)
		assert.Equal("OK", claims.Get("test"))
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

	t.Run("SetExpiration", func(t *testing.T) {
		assert := assert.New(t)

		jwter := NewJWT([]byte("key1"))
		token, err := jwter.Sign(map[string]interface{}{"test": "OK"})
		assert.Nil(err)
		claims, _ := jwter.Verify(token)
		assert.Equal("OK", claims.Get("test"))
		assert.Nil(claims.Get("exp"))

		jwter.SetExpiration(time.Second)
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
			jwter.SetMethods()
		})
		jwter.SetMethods(crypto.SigningMethodHS256, crypto.SigningMethodHS384)
		token, err := jwter.Sign(jwt.Claims{"test": "OK"}, crypto.SigningMethodHS384)
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
			claims, err := jwter.FromCtx(ctx)
			if err != nil {
				return err
			}
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
		app.UseHandler(jwter)
		app.Use(func(ctx *gear.Context) error {
			claims, err := jwter.FromCtx(ctx)
			if err != nil {
				return err
			}
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
		req.Headers["Authorization"] = "OAUTH2 " + token
		res, err := req.Get(host)
		assert.Nil(err)
		assert.Equal(200, res.StatusCode)

		body, _ := ioutil.ReadAll(res.Body)
		assert.Equal(gear.MIMEApplicationJSONCharsetUTF8, res.Header.Get(gear.HeaderContentType))
		assert.True(strings.Contains(string(body), `"hello":"world"`))
		res.Body.Close()
	})
}
