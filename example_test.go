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
	auther := auth.New([]byte("key_new"), []byte("key_old"))
	auther.JWT().SetIssuer("Gear")
	// auther.JWT().SetExpiration(time.Hour * 24)

	app := gear.New()
	app.UseHandler(auther)
	app.Use(func(ctx *gear.Context) error {
		claims, err := auther.FromCtx(ctx)
		if err != nil {
			return err // means Authentication failure.
		}
		return ctx.JSON(200, claims)
	})
	srv := app.Start()
	defer srv.Close()

	req := NewRequst()
	host := "http://" + srv.Addr().String()

	claims := jwt.Claims{}
	claims.Set("Hello", "world")
	token, _ := auther.JWT().Sign(claims)
	req.Headers["Authorization"] = "Bearer " + token
	res, _ := req.Get(host)
	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(body))
	// Output: {"Hello":"world","iss":"Gear"}
}
