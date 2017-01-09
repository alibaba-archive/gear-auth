// Package auth implements authorization and authentication with JWT, JWS, and JWE for Gear.

/*
Example:

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
    jwter := auth.NewJWT([]byte("key_new"), []byte("key_old"))
    jwter.SetIssuer("Gear")
    // jwter.SetExpiration(time.Hour * 24)

    app := gear.New()
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

Learn more at https://github.com/teambition/gear-auth
*/

package auth

// Version is Gear-Auth version
const Version = "v1.1.0"
