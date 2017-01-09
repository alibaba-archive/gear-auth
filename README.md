Gear-Auth
====
Auth library with JWT, JWS, and JWE for Gear.

[![Build Status](http://img.shields.io/travis/teambition/gear-auth.svg?style=flat-square)](https://travis-ci.org/teambition/gear-auth)
[![Coverage Status](http://img.shields.io/coveralls/teambition/gear-auth.svg?style=flat-square)](https://coveralls.io/r/teambition/gear-auth)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/teambition/gear-auth/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/teambition/gear-auth)


## Demo

### Create a token and verify it.
```go
jwter := NewJWT([]byte("key1"))
token, _ := jwter.Sign(jwt.Claims{"test": "OK"})
claims, _ := jwter.Verify(token)
fmt.Println(claims.Get("test"))
// Output: "OK"
```

### Create a token and verify it with ECDSA
```go
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
token, _ := jwter.Sign(jws.Claims{"test": "OK"})
fmt.Println(token)
// Output:  "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoiT0sifQ.MEQCIAy5-edjjRliSD4rgYTL02nuNka_n_tGUzDLEvHAKUcpAiAu3QkiPvB3sYO5ZAYJWCPdCk7lh4yYSy4z7VorZ893cQ"
claims, _ := jwter.Verify(token)
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
	jwter := auth.NewJWT([]byte("some_key")))
	jwter.SetIssuer("Gear")
	// jwter.SetExpiration(time.Hour * 24)

	app := gear.New()

	// use jwter as middleware, if authentication failure, next middleware will not run.
	app.UseHandler(jwter)

	app.Use(func(ctx *gear.Context) error {
		claims, err := jwter.FromCtx(ctx)
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