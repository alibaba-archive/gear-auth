package jwt

import (
	"fmt"
	"io/ioutil"
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

func TestGearAppHello(t *testing.T) {
	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		app := gear.New()
		jwter := &JWT{Keys: [][]byte{[]byte("my key")}, ExpiresIn: time.Minute}

		router := gear.NewRouter()

		router.Get("/", func(ctx *gear.Context) error {
			claims, err := jwter.FromCtx(ctx)
			if err != nil {
				return err
			}
			return ctx.JSON(200, claims)
		})

		router.Get("/token", func(ctx *gear.Context) error {
			claims := jws.Claims{}
			claims.Set("hello", "world")
			claims.SetIssuer("Gear")
			token, err := jwter.Sign(claims)
			if err == nil {
				ctx.Type(gear.MIMETextPlainCharsetUTF8)
				return ctx.End(200, token)
			}
			return err
		})

		app.UseHandler(router)
		srv := app.Start()
		defer srv.Close()

		req := NewRequst()
		host := "http://" + srv.Addr().String()

		res, err := req.Get(host)
		assert.Nil(err)
		assert.Equal(401, res.StatusCode)
		body, _ := res.Text()
		assert.Equal("No authorization token was found", body)

		res, err = req.Get(host + "/token")
		assert.Nil(err)
		assert.Equal(200, res.StatusCode)
		body, _ = res.Text()
		fmt.Println(111, body)

		req.Headers["Authorization"] = "BEARER " + body
		res, err = req.Get(host)
		assert.Nil(err)
		assert.Equal(200, res.StatusCode)
		buf, _ := ioutil.ReadAll(res.Body)
		fmt.Println(123, string(buf))
		res.Body.Close()
	})
}
