# Gear-Auth

Auth library base on JWT.

[![Build Status](http://img.shields.io/travis/teambition/gear-auth.svg?style=flat-square)](https://travis-ci.org/teambition/gear-auth)
[![Coverage Status](http://img.shields.io/coveralls/teambition/gear-auth.svg?style=flat-square)](https://coveralls.io/r/teambition/gear-auth)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/teambition/gear-auth/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/teambition/gear-auth)

## Crypto Library

https://github.com/teambition/crypto-go

## Demo

### Create a token and verify it

```go
auther := auth.New([]byte("key1"))
token, _ := auther.JWT().Sign(jwt.Claims{"test": "OK"})
claims, _ := auther.JWT().Verify(token)
fmt.Println(claims.Get("test"))
// Output: "OK"
```

### jwt with ED25519 and HS256 Alg backup

```go
package main

import (
	"fmt"

	josecrypto "github.com/SermoDigital/jose/crypto"
	josejws "github.com/SermoDigital/jose/jws"
	"github.com/teambition/gear-auth/jwt"
	"github.com/teambition/gear-auth/jwt/ed25519"
)

func main() {
	publicKey, privateKey := ed25519.GenerateKey()
	fmt.Println("publicKey:", publicKey)
	fmt.Println("privateKey:", privateKey)

	keyPair, err := ed25519.KeyPairFrom(publicKey, privateKey)
	if err != nil {
		panic(err)
	}

	jwter := jwt.New(keyPair)
	jwter.SetMethods(ed25519.SigningMethodED25519)
	jwter.SetBackupSigning(josecrypto.SigningMethodHS256, []byte("old key 1"), []byte("old key 2"))

	token, err := jwter.Sign(josejws.Claims{"test": "OK"})
	fmt.Println(err, token)

	claims, err := jwter.Verify(token)
	fmt.Println(err, claims)

	// claims, err = jwter.Verify(some_old_HS256_token)
}
```

### Use with Gear

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
  auther := auth.New([]byte("some_key"))
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
  req.Headers["Authorization"] = "Bearer " + token
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
Copyright &copy; 2016-2018 [Teambition](https://www.teambition.com).
