package auth

import (
	"net/http"
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

		jwter := New(JWTOptions{Keys: [][]byte{[]byte("my key")}, ExpiresIn: time.Minute})
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
		assert.Equal("No authorization token was found", body)
	})

	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		jwter := New(JWTOptions{Keys: [][]byte{[]byte("my key")}, ExpiresIn: time.Minute})
		app := gear.New()
		app.UseHandler(jwter)
		app.Use(func(ctx *gear.Context) error {
			return ctx.End(204)
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
		assert.Equal(204, res.StatusCode)
		res.Body.Close()
	})
}
