// Package auth implements authorization and authorization with JWT, JWS, and JWE for Gear.

package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/teambition/gear"
)

// JWT is
type JWT struct {
	keys      []interface{}
	expiresIn time.Duration

	// Issuer represents JWTs Issuer, OPTIONAL. Default to ""
	Issuer string
	// Methods is Signing Method set that can be used. Default to [crypto.SigningMethodHS256]
	Methods []crypto.SigningMethod
	// Validator
	Validator *jwt.Validator
	GetToken  func(ctx *gear.Context) (token string)
}

// New returns a JWT module.
func New(keys []interface{}, expiresIn time.Duration) *JWT {
	j := &JWT{Methods: []crypto.SigningMethod{crypto.SigningMethodHS256}}

	if len(keys) == 0 || keys[0] == nil {
		panic(errors.New("Keys not exists"))
	}
	j.keys = keys

	if expiresIn <= 0 {
		panic(errors.New("ExpiresIn not exists"))
	}
	j.expiresIn = expiresIn

	j.GetToken = func(ctx *gear.Context) (token string) {
		if auth := ctx.Get("Authorization"); strings.HasPrefix(auth, "BEARER ") {
			token = auth[7:]
		} else {
			token = ctx.Param("access_token")
		}
		return
	}
	return j
}

// Sign return ...
func (j *JWT) Sign(claims jws.Claims) ([]byte, error) {

	key := j.keys[0]
	if j.Issuer != "" {
		claims.SetIssuer(j.Issuer)
	}
	claims.SetIssuedAt(time.Now())
	claims.SetExpiration(time.Now().Add(j.expiresIn))
	token := jws.NewJWT(claims, j.Methods[0])
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
	res, err := jws.ParseJWT([]byte(token))
	if err == nil {
		v := []*jwt.Validator{}
		if j.Validator != nil {
			v = append(v, j.Validator)
		}
		for _, key := range j.keys { // key rotation
			for _, method := range j.Methods { // method rotation
				if err = res.Validate(key, method, v...); err == nil {
					return res.Claims(), nil
				}
			}
		}
	}
	return nil, &gear.Error{Code: 401, Msg: err.Error()}
}

// New implements gear.Any interface
func (j *JWT) New(ctx *gear.Context) (interface{}, error) {
	if token := j.GetToken(ctx); token != "" {
		return j.Verify([]byte(token))
	}
	return nil, &gear.Error{Code: 401, Msg: "No token was found"}
}

// FromCtx return
func (j *JWT) FromCtx(ctx *gear.Context) (jwt.Claims, error) {
	any, err := ctx.Any(j)
	if err == nil {
		return any.(jwt.Claims), nil
	}
	return nil, err
}

// Serve implements gear.Handler interface. We can use it as middleware.
func (j *JWT) Serve(ctx *gear.Context) (err error) {
	_, err = ctx.Any(j)
	return
}
