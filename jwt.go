package auth

import (
	"net/http"

	"github.com/allenai/beaker-auth/keystore"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/pkg/errors"
)

// The key ID header is optional. We use it to enable efficient key rotation. We
// can look up keys directly by ID rather than walking all keys until one works.
// See https://tools.ietf.org/html/rfc7515#section-4.1.4
const keyIDHeader = "kid"

// Claims describes custom claims for a JWT token.
type Claims struct {
	Scopes []Scope `json:"scopes"`
	jwt.StandardClaims
}

// Valid implements the jwt.Claim interface.
func (c Claims) Valid() error {
	for _, s := range c.Scopes {
		if err := s.validate(); err != nil {
			return err
		}
	}
	return c.StandardClaims.Valid()
}

// Signer is a signing authority for creating authentication tokens.
type Signer struct {
	keyStore keystore.KeyStore
	keyFunc  jwt.Keyfunc
}

// NewSigner creates a token factory given a persistent key store.
func NewSigner(ks keystore.KeyStore) *Signer {
	return &Signer{
		keyStore: ks,
		keyFunc: func(t *jwt.Token) (interface{}, error) {
			// This will fail gracefully if the key is missing or non-string.
			id, ok := t.Header[keyIDHeader].(string)
			if !ok {
				return nil, errors.New("token signed with unknown key")
			}
			return ks.KeyFromID(id)
		},
	}
}

// NewToken creates a signed token with the given claims.
func (s *Signer) NewToken(claims *Claims) (string, error) {
	kid, key, err := s.keyStore.NewKey()
	if err != nil {
		return "", errors.Wrap(err, "token: failed to create key")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, *claims)
	token.Header[keyIDHeader] = kid

	signed, err := token.SignedString(key)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return signed, nil
}

// AuthRequest parses a signed token's claims from an HTTP request.
func (s *Signer) AuthRequest(r *http.Request) (*Claims, error) {
	var claims Claims

	ex := request.AuthorizationHeaderExtractor
	opts := []request.ParseFromRequestOption{
		request.WithClaims(&claims),
		request.WithParser(&jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Alg()}}),
	}
	token, err := request.ParseFromRequest(r, ex, s.keyFunc, opts...)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// The JWT parser should just unmarshal and return the struct we gave it.
	if token.Claims != &claims {
		panic("expected token claims to match provided address")
	}

	return &claims, nil
}
