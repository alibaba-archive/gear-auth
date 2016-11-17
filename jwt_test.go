package auth

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/mozillazg/request"
	"github.com/stretchr/testify/assert"
	"github.com/teambition/gear"
)

func NewRequst() *request.Request {
	c := &http.Client{}
	return request.NewRequest(c)
}

func TestAuthJWT(t *testing.T) {
	t.Run("should 401", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]interface{}{"my key"}, time.Minute)
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
		assert.Equal("No token was found", body)
	})

	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New([]interface{}{[]byte("my key")}, time.Minute)
		app := gear.New()
		app.Use(jwter.Serve)
		app.Use(func(ctx *gear.Context) error {
			claims, err := jwter.FromCtx(ctx)
			if err != nil {
				return err
			}
			assert.Equal("world", claims.Get("hello").(string))
			return ctx.JSON(200, claims)
		})
		srv := app.Start()
		defer srv.Close()

		req := NewRequst()
		host := "http://" + srv.Addr().String()

		claims := jws.Claims{}
		claims.Set("hello", "world")
		token, _ := jwter.Sign(claims)
		req.Headers["Authorization"] = "BEARER " + string(token)
		res, err := req.Get(host)
		assert.Nil(err)
		assert.Equal(200, res.StatusCode)

		body, _ := ioutil.ReadAll(res.Body)
		assert.Equal(gear.MIMEApplicationJSONCharsetUTF8, res.Header.Get(gear.HeaderContentType))
		assert.True(strings.Contains(string(body), `"hello":"world"`))
		res.Body.Close()
	})
}
