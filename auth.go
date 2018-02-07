package auth

import (
	"strings"

	josejwt "github.com/SermoDigital/jose/jwt"
	"github.com/teambition/gear"
	"github.com/teambition/gear-auth/jwt"
)

// Version ...
const Version = "1.6.0"

// TokenExtractor is a function that takes a gear.Context as input and
// returns either a string token or an empty string. Default to:
//
//  func(ctx *gear.Context) (token string) {
//  	if val := ctx.Get("Authorization"); strings.HasPrefix(val, "BEARER ") {
//  		token = val[7:]
//  	} else {
//  		token = ctx.Param("access_token")
//  	}
//  	return
//  }
//
type TokenExtractor func(ctx *gear.Context) (token string)

// Auth is helper type. It combine JWT and Crypto object, and some useful mothod for JWT.
// You can use it as a gear middleware.
type Auth struct {
	j       *jwt.JWT
	ex      TokenExtractor
	skipper func(*gear.Context) bool
}

// New returns a Auth instance.
//
//  auther := auth.New([]byte("my key"))
//
func New(keys ...interface{}) *Auth {
	a := new(Auth)
	a.SetJWT(jwt.New(keys...))
	a.ex = func(ctx *gear.Context) (token string) {
		if val := ctx.GetHeader("Authorization"); strings.HasPrefix(val, "Bearer ") {
			token = val[7:]
		} else {
			token = ctx.Query("access_token")
		}
		return
	}
	return a
}

// JWT returns internal JWT instance.
func (a *Auth) JWT() *jwt.JWT {
	return a.j
}

// SetJWT set a JWT instance to auth.
func (a *Auth) SetJWT(j *jwt.JWT) {
	a.j = j
}

// SetTokenParser set a custom tokenExtractor to auth.
func (a *Auth) SetTokenParser(ex TokenExtractor) {
	a.ex = ex
}

// SetSkipper set a skip function to auth.
// If skip function return true, the auth middleware process will be skipped.
func (a *Auth) SetSkipper(fn func(*gear.Context) bool) *Auth {
	a.skipper = fn
	return a
}

// New implements gear.Any interface, then we can use it with ctx.Any:
//
//  any, err := ctx.Any(auther)
//  if err != nil {
//  	return err
//  }
//  claims := any.(jwt.Claims)
//
// that is auth.FromCtx doing for us.
//
func (a *Auth) New(ctx *gear.Context) (val interface{}, err error) {
	if token := a.ex(ctx); token != "" {
		val, err = a.j.Verify(token)
	}
	if val == nil {
		// create a empty jwt.Claims
		val = josejwt.Claims{}
		if err == nil {
			err = gear.ErrUnauthorized.WithMsg("no token found")
		} else {
			err = gear.ErrUnauthorized.From(err)
		}
	}
	ctx.SetAny(a, val)
	return
}

// FromCtx will parse and validate token from the ctx, and return it as jwt.Claims.
// If token not exists or validate failure, a error and a empty jwt.Claims instance returned.
//
//  claims, err := auther.FromCtx(ctx)
//  fmt.Println(claims, err)
//
func (a *Auth) FromCtx(ctx *gear.Context) (josejwt.Claims, error) {
	val, err := ctx.Any(a)
	return val.(josejwt.Claims), err
}

// Serve implements gear.Handler interface. We can use it as middleware.
// It will parse and validate token from the ctx, if succeed, gear's middleware process
// will go on, otherwise process ended and a 401 error will be to respond to client.
//
//  app := gear.New()
//  auther := auth.New()
//  app.UseHandler(auther)
//  // or
//  app.Use(auther.Serve)
//
func (a *Auth) Serve(ctx *gear.Context) error {
	if a.skipper != nil && a.skipper(ctx) {
		return nil
	}
	_, err := ctx.Any(a)
	return err
}
