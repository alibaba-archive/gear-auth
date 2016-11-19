package auth_test

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/SermoDigital/jose/jwt"
	"github.com/mozillazg/request"
	"github.com/teambition/gear"
	"github.com/teambition/gear-auth"
)

func NewRequst() *request.Request {
	c := &http.Client{}
	return request.NewRequest(c)
}

func ExampleGearAuth() {
	jwter := auth.NewJWT([]byte("key_new"), []byte("key_old"))
	jwter.SetIssuer("Gear")
	// jwter.SetExpiration(time.Hour * 24)

	app := gear.New()
	app.UseHandler(jwter)
	app.Use(func(ctx *gear.Context) error {
		return ctx.JSON(200, jwter.FromCtx(ctx))
	})
	srv := app.Start()
	defer srv.Close()

	req := NewRequst()
	host := "http://" + srv.Addr().String()

	claims := jwt.Claims{}
	claims.Set("Hello", "world")
	token, _ := jwter.Sign(claims)
	req.Headers["Authorization"] = "BEARER " + token
	res, _ := req.Get(host)
	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(body))
	// Output: {"Hello":"world","iss":"Gear"}
}
