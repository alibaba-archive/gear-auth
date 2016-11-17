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

// JWTOptions is options for JWT
type JWTOptions struct {
	Keys      [][]byte // key rotation
	ExpiresIn time.Duration
	Issuer    string   // OPTIONAL
	Algs      []string // Algs that can be used. Default to ["HS256"]
}

// JWT is
type JWT struct {
	keys      [][]byte // key rotation
	expiresIn time.Duration
	issuer    string   // OPTIONAL
	algs      []string // Algs that can be used. Default to ["HS256"]
}

// New returns a JWT module.
func New(opts JWTOptions) *JWT {
	j := &JWT{issuer: opts.Issuer}
	if len(opts.Keys) == 0 {
		panic(errors.New("Keys not exists"))
	}
	j.keys = opts.Keys

	if opts.ExpiresIn <= 0 {
		panic(errors.New("ExpiresIn not exists"))
	}
	j.expiresIn = opts.ExpiresIn

	if len(opts.Algs) == 0 {
		j.algs = []string{"HS256"}
	} else {
		j.algs = opts.Algs
	}

	return j
}

// Sign return ...
func (j *JWT) Sign(claims jws.Claims) ([]byte, error) {

	key := j.keys[0]
	if j.issuer != "" {
		claims.SetIssuer(j.issuer)
	}
	claims.SetIssuedAt(time.Now())
	claims.SetExpiration(time.Now().Add(j.expiresIn))
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
	res, err := jws.ParseJWT([]byte(token))
	if err == nil {
		for _, key := range j.keys {
			if err = res.Validate(key, crypto.SigningMethodHS256); err == nil {
				return res.Claims(), nil
			}
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

func (j *JWT) getSigningMethod(alg string) (method crypto.SigningMethod) {
	for _, name := range j.algs {
		if name == alg {
			return jws.GetSigningMethod(alg)
		}
	}
	return
}
