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

// TokenExtractor is a function that takes a gear.Context as input and
// returns either a string token or an empty string. Default to:
//
//  func(ctx *gear.Context) (token string) {
//  	if auth := ctx.Get("Authorization"); strings.HasPrefix(auth, "BEARER ") {
//  		token = auth[7:]
//  	} else {
//  		token = ctx.Param("access_token")
//  	}
//  	return
//  }
//
type TokenExtractor func(ctx *gear.Context) (token string)

// KeyPair represents key struct for ECDSA, RS/PS SigningMethod.
type KeyPair struct {
	PrivateKey interface{}
	PublicKey  interface{}
}

// JWT represents a module. it can be use to create, decode or verify JWT token.
// It can be used as gear middleware to authenticate client too.
type JWT struct {
	keys      []interface{}
	expiresIn time.Duration
	issuer    string
	method    crypto.SigningMethod
	validator []*jwt.Validator
	extractor TokenExtractor
}

// NewJWT returns a JWT instance, jwter.
// if key omit, jwter will use crypto.Unsecured as signing method.
// Otherwise crypto.SigningMethodHS256 will be used. You can change it by jwter.SetMethods.
func NewJWT(keys ...interface{}) *JWT {
	j := &JWT{method: crypto.Unsecured}
	j.keys = keys
	if len(keys) == 0 {
		j.keys = []interface{}{nil}
	} else {
		j.method = crypto.SigningMethodHS256
	}
	j.extractor = func(ctx *gear.Context) (token string) {
		if auth := ctx.Get("Authorization"); strings.HasPrefix(auth, "BEARER ") {
			token = auth[7:]
		} else {
			token = ctx.Query("access_token")
		}
		return
	}
	return j
}

// Sign creates a JWT token with the given content and optional expiresIn.
//
//  token1, err1 := jwter.Sign(map[string]interface{}{"UserId": "xxxxx"})
//  // or
//  claims := jwt.Claims{} // or claims := jws.Claims{}
//  claims.Set("hello", "world")
//  token2, err2 := jwter.Sign(claims)
//
// if expiresIn <= 0, expiration will not be set to claims:
//
//  token1, err1 := jwter.Sign(map[string]interface{}{"UserId": "xxxxx"}, time.Duration(0))
//
func (j *JWT) Sign(content map[string]interface{}, expiresIn ...time.Duration) (string, error) {
	claims := jwt.Claims(content)
	if j.issuer != "" {
		claims.SetIssuer(j.issuer)
	}
	if len(expiresIn) > 0 {
		if expiresIn[0] > 0 {
			claims.SetExpiration(time.Now().Add(expiresIn[0]))
		}
	} else if j.expiresIn > 0 {
		claims.SetExpiration(time.Now().Add(j.expiresIn))
	}

	var key interface{} = j.keys[0]
	return Sign(claims, j.method, key)
}

// Decode parse a string token, but don't validate it.
func (j *JWT) Decode(token string) (jwt.Claims, error) {
	return Decode(token)
}

// Verify parse a string token and validate it with keys, signingMethods and validator in rotationally.
func (j *JWT) Verify(token string) (jwt.Claims, error) {
	jwtToken, err := jws.ParseJWT([]byte(token))
	if err == nil {
		for _, key := range j.keys { // key rotation
			if k, ok := key.(KeyPair); ok { // try to extract PublicKey
				key = k.PublicKey
			}
			if err = jwtToken.Validate(key, j.method, j.validator...); err == nil {
				return jwtToken.Claims(), nil
			}
		}
	}
	return nil, &gear.Error{Code: 401, Msg: err.Error()}
}

// SetIssuer set a issuer to jwter.
// Default to "", no "iss" will be added.
func (j *JWT) SetIssuer(issuer string) {
	j.issuer = issuer
}

// GetExpiresIn returns jwter's expiration.
func (j *JWT) GetExpiresIn() time.Duration {
	return j.expiresIn
}

// SetExpiresIn set a expire duration to jwter.
// Default to 0, no "exp" will be added.
func (j *JWT) SetExpiresIn(expiresIn time.Duration) {
	j.expiresIn = expiresIn
}

// SetMethods set one or more signing methods which can be used rotational.
func (j *JWT) SetMethods(method crypto.SigningMethod) {
	if method == nil {
		panic(errors.New("Invalid signing method"))
	}
	j.method = method
}

// SetValidator set a custom jwt.Validator to jwter. Default to nil.
func (j *JWT) SetValidator(validator *jwt.Validator) {
	if validator == nil {
		panic(errors.New("Invalid validator"))
	}
	j.validator = []*jwt.Validator{validator}
}

// SetTokenParser set a custom tokenExtractor to jwter. Default to:
//
//  func(ctx *gear.Context) (token string) {
//  	if auth := ctx.Get("Authorization"); strings.HasPrefix(auth, "BEARER ") {
//  		token = auth[7:]
//  	} else {
//  		token = ctx.Query("access_token")
//  	}
//  	return
//  }
//
func (j *JWT) SetTokenParser(extractor TokenExtractor) {
	j.extractor = extractor
}

// New implements gear.Any interface, then we can use it with ctx.Any:
//
//  any, err := ctx.Any(jwter)
//  if err != nil {
//  	return err
//  }
//  claims := any.(jwt.Claims)
//
// that is jwter.FromCtx doing for us.
//
func (j *JWT) New(ctx *gear.Context) (interface{}, error) {
	if token := j.extractor(ctx); token != "" {
		return j.Verify(token)
	}
	return nil, &gear.Error{Code: 401, Msg: "No token found"}
}

// FromCtx will parse and validate token from the ctx, and return it as jwt.Claims.
// If token not exists or validate failure, a error and a empty jwt.Claims instance returned.
//
//  claims, err := jwter.FromCtx(ctx)
//  fmt.Println(claims, err)
//
func (j *JWT) FromCtx(ctx *gear.Context) (jwt.Claims, error) {
	any, err := ctx.Any(j)
	if err == nil {
		return any.(jwt.Claims), nil
	}
	claims := jwt.Claims{}
	ctx.SetAny(j, claims)
	return claims, err
}

// Serve implements gear.Handler interface. We can use it as middleware.
// It will parse and validate token from the ctx, if succeed, gear's middleware process
// will go on, otherwise process ended and a 401 error will be to respond to client.
//
//  app := gear.New()
//  jwter := auth.New()
//  app.UseHandler(jwter)
//  // or
//  app.Use(jwter.Serve)
//
func (j *JWT) Serve(ctx *gear.Context) error {
	claims, err := j.New(ctx)
	if err == nil {
		ctx.SetAny(j, claims)
	}
	return err
}

// Sign creates a JWT token with the given claims, signing method and key.
func Sign(claims jwt.Claims, method crypto.SigningMethod, key interface{}) (string, error) {
	if k, ok := key.(KeyPair); ok { // try to extract PrivateKey
		key = k.PrivateKey
	}
	buf, err := jws.NewJWT(jws.Claims(claims), method).Serialize(key)
	if err == nil {
		return string(buf), nil
	}
	return "", err
}

// Decode parse a string token, but don't validate it.
func Decode(token string) (jwt.Claims, error) {
	jwtToken, err := jws.ParseJWT([]byte(token))
	if err == nil {
		return jwtToken.Claims(), nil
	}
	return nil, &gear.Error{Code: 401, Msg: err.Error()}
}

// Verify parse a string token and validate it with keys, signingMethods in rotationally.
func Verify(token string, method crypto.SigningMethod, keys ...interface{}) (jwt.Claims, error) {
	jwtToken, err := jws.ParseJWT([]byte(token))
	if err == nil {
		for _, key := range keys { // key rotation
			if k, ok := key.(KeyPair); ok { // try to extract PublicKey
				key = k.PublicKey
			}
			if err = jwtToken.Validate(key, method); err == nil {
				return jwtToken.Claims(), nil
			}
		}
	}
	return nil, &gear.Error{Code: 401, Msg: err.Error()}
}
