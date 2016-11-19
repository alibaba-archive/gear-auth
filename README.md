Gear-Auth
====
Auth library with JWT, JWS, and JWE for Gear.

[![Build Status](http://img.shields.io/travis/teambition/gear-auth.svg?style=flat-square)](https://travis-ci.org/teambition/gear-auth)
[![Coverage Status](http://img.shields.io/coveralls/teambition/gear-auth.svg?style=flat-square)](https://coveralls.io/r/teambition/gear-auth)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/teambition/gear-auth/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/teambition/gear-auth)


## Demo
```go
package main

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

func main() {
	jwter := auth.NewJWT([]byte("some_key")))
	jwter.SetIssuer("Gear")
	// jwter.SetExpiration(time.Hour * 24)

	app := gear.New()

	// use jwter as middleware, if authentication failure, next middleware will not run.
	app.UseHandler(jwter)

	app.Use(func(ctx *gear.Context) error {
		// get JWT claims from the ctx. claims should always has content(not empty)
		// because of authentication success in previous middleware.
		claims := jwter.FromCtx(ctx)
		return ctx.JSON(200, claims)
	})
	srv := app.Start()
	defer srv.Close()

	req := NewRequst()
	host := "http://" + srv.Addr().String()

	// create a token
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
```

## Documentation

The docs can be found at [godoc.org](https://godoc.org/github.com/teambition/gear-auth), as usual.

## License
Gear-Auth is licensed under the [MIT](https://github.com/teambition/gear-auth/blob/master/LICENSE) license.
Copyright &copy; 2016 [Teambition](https://www.teambition.com).