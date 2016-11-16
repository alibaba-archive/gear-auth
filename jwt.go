// Package jwt implements a Json web token (JWT) middleware for Gear.

// package jwt

package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/teambition/gear"
)

// JWT is
type JWT struct {
	Keys      [][]byte
	ExpiresIn time.Duration
}

// Sign return ...
func (j *JWT) Sign(claims jws.Claims) ([]byte, error) {
	if len(j.Keys) == 0 {
		panic(errors.New("Keys not exists"))
	}
	key := j.Keys[0]
	claims.SetExpiration(time.Now().Add(j.ExpiresIn))
	claims.SetIssuedAt(time.Now())
	token := jws.NewJWT(claims, crypto.SigningMethodHS256)
	return token.Serialize(key)
}

// Decode return ...
func (j *JWT) Decode(token []byte) (jwt.Claims, error) {
	res, err := jws.ParseJWT([]byte(token))
	if err == nil {
		return res.Claims(), nil
	}
	return nil, &gear.Error{Code: 401, Msg: err.Error()}
}

// Verify return ...
func (j *JWT) Verify(token []byte) (jwt.Claims, error) {
	if len(j.Keys) == 0 {
		panic(errors.New("Keys not exists"))
	}

	res, err := jws.ParseJWT([]byte(token))
	if err == nil {
		for _, key := range j.Keys {
			if err = res.Validate(key, crypto.SigningMethodHS256); err == nil {
				return res.Claims(), nil
			}
			fmt.Println(333, err)
		}
	}
	return nil, &gear.Error{Code: 401, Msg: err.Error()}
}

// New implements gear.Any interface
func (j *JWT) New(ctx *gear.Context) (interface{}, error) {
	if ah := ctx.Get("Authorization"); len(ah) > 7 && strings.EqualFold(ah[0:7], "BEARER ") {
		return j.Verify([]byte(ah[7:]))
	}
	return nil, &gear.Error{Code: 401, Msg: "No authorization token was found"}
}

// FromCtx return
func (j *JWT) FromCtx(ctx *gear.Context) (jwt.Claims, error) {
	if any, err := ctx.Any(j); err == nil {
		return any.(jwt.Claims), nil
	} else {
		return nil, err
	}
}
