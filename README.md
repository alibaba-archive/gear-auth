Gear-Auth
====
Auth library with some useful JWT and Crypto methods.

[![Build Status](http://img.shields.io/travis/teambition/gear-auth.svg?style=flat-square)](https://travis-ci.org/teambition/gear-auth)
[![Coverage Status](http://img.shields.io/coveralls/teambition/gear-auth.svg?style=flat-square)](https://coveralls.io/r/teambition/gear-auth)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/teambition/gear-auth/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/teambition/gear-auth)


## Demo

### Create a token and verify it.
```go
auther := auth.New([]byte("key1"))
token, _ := auther.JWT().Sign(jwt.Claims{"test": "OK"})
claims, _ := auther.JWT().Verify(token)
fmt.Println(claims.Get("test"))
// Output: "OK"
```

### Use with Gear.
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
	auther := auth.New([]byte("some_key")))
	auther.JWT().SetIssuer("Gear")
	// auther.JWT().SetExpiration(time.Hour * 24)

	app := gear.New()

	// use auther as middleware, if authentication failure, next middleware will not run.
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

	// create a token
	claims := jwt.Claims{}
	claims.Set("Hello", "world")
	token, _ := auther.JWT().Sign(claims)
	req.Headers["Authorization"] = "BEARER " + token
	res, _ := req.Get(host)
	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)
	fmt.Println(string(body))
	// Output: {"Hello":"world","iss":"Gear"}
}
```

## Documentation

https://godoc.org/github.com/teambition/gear-auth

## License
Gear-Auth is licensed under the [MIT](https://github.com/teambition/gear-auth/blob/master/LICENSE) license.
Copyright &copy; 2016 [Teambition](https://www.teambition.com).