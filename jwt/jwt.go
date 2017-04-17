package jwt

import (
	"errors"
	"net/textproto"
	"time"

	josecrypto "github.com/SermoDigital/jose/crypto"
	josejws "github.com/SermoDigital/jose/jws"
	josejwt "github.com/SermoDigital/jose/jwt"
)

// KeyPair represents key struct for ECDSA, RS/PS SigningMethod.
type KeyPair struct {
	PrivateKey interface{}
	PublicKey  interface{}
}

// JWT represents a module. it can be use to create, decode or verify JWT token.
type JWT struct {
	keys      rotating
	expiresIn time.Duration
	issuer    string
	method    josecrypto.SigningMethod
	validator []*josejwt.Validator
}

// New returns a JWT instance.
// if key omit, jwt will use crypto.Unsecured as signing method.
// Otherwise crypto.SigningMethodHS256 will be used. You can change it by jwt.SetMethods.
func New(keys ...interface{}) *JWT {
	j := &JWT{method: josecrypto.Unsecured}
	j.keys = keys
	if len(keys) == 0 {
		j.keys = []interface{}{nil}
	} else {
		j.method = josecrypto.SigningMethodHS256
	}
	return j
}

// Sign creates a JWT token with the given content and optional expiresIn.
//
//  token1, err1 := jwt.Sign(map[string]interface{}{"UserId": "xxxxx"})
//  // or
//  claims := josejwt.Claims{} // or claims := josejws.Claims{}
//  claims.Set("hello", "world")
//  token2, err2 := jwt.Sign(claims)
//
// if expiresIn <= 0, expiration will not be set to claims:
//
//  token1, err1 := jwt.Sign(map[string]interface{}{"UserId": "xxxxx"}, time.Duration(0))
//
func (j *JWT) Sign(content map[string]interface{}, expiresIn ...time.Duration) (string, error) {
	claims := josejwt.Claims(content)
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
func (j *JWT) Decode(token string) (josejwt.Claims, error) {
	return Decode(token)
}

// Verify parse a string token and validate it with keys, signingMethods and validator in rotationally.
func (j *JWT) Verify(token string) (claims josejwt.Claims, err error) {
	jwtToken, err := josejws.ParseJWT([]byte(token))
	if err == nil {
		if j.keys.Verify(func(key interface{}) bool { // key rotation
			if k, ok := key.(KeyPair); ok { // try to extract PublicKey
				key = k.PublicKey
			}
			if err = jwtToken.Validate(key, j.method, j.validator...); err == nil {
				claims = jwtToken.Claims()
				return true
			}
			return false
		}) >= 0 {
			return
		}
	}
	return nil, &textproto.Error{Code: 401, Msg: err.Error()}
}

// SetIssuer set a issuer to jwt.
// Default to "", no "iss" will be added.
func (j *JWT) SetIssuer(issuer string) {
	j.issuer = issuer
}

// GetExpiresIn returns jwt's expiration.
func (j *JWT) GetExpiresIn() time.Duration {
	return j.expiresIn
}

// SetExpiresIn set a expire duration to jwt.
// Default to 0, no "exp" will be added.
func (j *JWT) SetExpiresIn(expiresIn time.Duration) {
	j.expiresIn = expiresIn
}

// SetKeys set new keys to jwt.
func (j *JWT) SetKeys(keys ...interface{}) {
	if len(keys) == 0 || keys[0] == nil {
		panic(errors.New("invalid keys"))
	}
	j.keys = keys
}

// SetMethods set one or more signing methods which can be used rotational.
func (j *JWT) SetMethods(method josecrypto.SigningMethod) {
	if method == nil {
		panic(errors.New("invalid signing method"))
	}
	j.method = method
}

// SetValidator set a custom jwt.Validator to jwt. Default to nil.
func (j *JWT) SetValidator(validator *josejwt.Validator) {
	if validator == nil {
		panic(errors.New("invalid validator"))
	}
	j.validator = []*josejwt.Validator{validator}
}

// Sign creates a JWT token with the given claims, signing method and key.
func Sign(claims josejwt.Claims, method josecrypto.SigningMethod, key interface{}) (string, error) {
	if k, ok := key.(KeyPair); ok { // try to extract PrivateKey
		key = k.PrivateKey
	}
	buf, err := josejws.NewJWT(josejws.Claims(claims), method).Serialize(key)
	if err == nil {
		return string(buf), nil
	}
	return "", err
}

// Decode parse a string token, but don't validate it.
func Decode(token string) (josejwt.Claims, error) {
	jwtToken, err := josejws.ParseJWT([]byte(token))
	if err == nil {
		return jwtToken.Claims(), nil
	}
	return nil, err
}

// Verify parse a string token and validate it with keys, signingMethods in rotationally.
func Verify(token string, method josecrypto.SigningMethod, keys ...interface{}) (claims josejwt.Claims, err error) {
	jwtToken, err := josejws.ParseJWT([]byte(token))
	if err == nil {
		if rotating(keys).Verify(func(key interface{}) bool {
			if k, ok := key.(KeyPair); ok { // try to extract PublicKey
				key = k.PublicKey
			}
			if err = jwtToken.Validate(key, method); err == nil {
				claims = jwtToken.Claims()
				return true
			}
			return false
		}) >= 0 {
			return
		}
	}
	return nil, &textproto.Error{Code: 401, Msg: err.Error()}
}

type rotating []interface{}

func (r rotating) Verify(v func(interface{}) bool) (index int) {
	for i, key := range r { // key rotation
		if v(key) {
			return i
		}
	}
	return -1
}

// StrToKeys converts string slice to keys slice.
func StrToKeys(keys ...string) (res []interface{}) {
	for _, key := range keys {
		res = append(res, []byte(key))
	}
	return
}
