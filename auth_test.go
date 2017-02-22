package auth

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/mozillazg/request"
	"github.com/stretchr/testify/assert"
	"github.com/teambition/gear"
	"github.com/teambition/gear-auth/crypto"
)

func NewRequst() *request.Request {
	c := &http.Client{}
	return request.NewRequest(c)
}

func TestGearAuth(t *testing.T) {
	t.Run("should 401", func(t *testing.T) {
		assert := assert.New(t)

		a := New([]byte("my key"))
		app := gear.New()
		app.UseHandler(a)
		srv := app.Start()
		defer srv.Close()

		req := NewRequst()
		host := "http://" + srv.Addr().String()

		res, err := req.Get(host)
		assert.Nil(err)
		assert.Equal(401, res.StatusCode)
		body, _ := res.Text()
		assert.Equal("no token found", body)

		a1 := New([]byte("wrong key"))
		claims := jwt.Claims{}
		claims.Set("hello", "world")
		token, _ := a1.JWT().Sign(claims)
		req.Headers["Authorization"] = "Bearer " + token
		res, err = req.Get(host)
		assert.Nil(err)
		assert.Equal(401, res.StatusCode)
	})

	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		a := New([]byte("my key 1"), []byte("my key 2"))
		app := gear.New()
		app.Use(a.Serve)
		app.Use(func(ctx *gear.Context) error {
			claims, _ := a.FromCtx(ctx)
			assert.Equal("world", claims.Get("hello"))
			return ctx.JSON(200, claims)
		})
		srv := app.Start()
		defer srv.Close()

		req := NewRequst()
		host := "http://" + srv.Addr().String()

		claims := jwt.Claims{}
		claims.Set("hello", "world")
		token, _ := a.JWT().Sign(claims)
		req.Headers["Authorization"] = "Bearer " + token
		res, err := req.Get(host)
		assert.Nil(err)
		assert.Equal(200, res.StatusCode)

		body, _ := ioutil.ReadAll(res.Body)
		assert.Equal(gear.MIMEApplicationJSONCharsetUTF8, res.Header.Get(gear.HeaderContentType))
		assert.True(strings.Contains(string(body), `"hello":"world"`))
		res.Body.Close()

		a1 := New([]byte("my key 2"))
		claims1 := jws.Claims{}
		claims1.Set("hello", "world")
		token, _ = a1.JWT().Sign(claims1)

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

		a := New([]byte("my key 1"))
		a.SetTokenParser(func(ctx *gear.Context) string {
			if auth := ctx.Get("Authorization"); strings.HasPrefix(auth, "OAUTH2 ") {
				return auth[7:]
			}
			return ""
		})
		app := gear.New()
		app.Use(func(ctx *gear.Context) error {
			claims, err := a.FromCtx(ctx)
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
		token, _ := a.JWT().Sign(claims)
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

	t.Run("should work with Crypto", func(t *testing.T) {
		assert := assert.New(t)

		a := New([]byte("my key 1"))
		assert.Nil(a.Crypto())
		c := crypto.New([]byte("my key 1"))
		a.SetCrypto(c)
		assert.Equal(c, a.Crypto())
	})
}
