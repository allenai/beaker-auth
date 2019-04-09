package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/allenai/beaker-auth/keystore/mocks"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewToken(t *testing.T) {
	tests := map[string]struct {
		KeyID       string
		Key         []byte
		KeyErr      error
		Claims      Claims
		ExpectedErr string
	}{
		"UnknownKey": {
			KeyID:       "abc123",
			KeyErr:      errors.New("something happened"),
			ExpectedErr: "token: failed to get key: something happened",
		},
		"Success": {
			KeyID: "abc123",
			Key:   []byte("key"),
			Claims: Claims{
				Scopes: []Scope{{Permission: Read, Class: "stuff"}},
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: time.Now().Add(5 * time.Second).Unix(),
				},
			},
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		ks := &mocks.KeyStore{}
		ks.On("KeyFromID", test.KeyID).Return(test.Key, test.KeyErr)

		s := NewSigner(ks)
		token, err := s.NewToken(test.KeyID, &test.Claims)
		if test.ExpectedErr != "" {
			assert.EqualError(t, err, test.ExpectedErr)
			continue
		}
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	}
}

func TestAuthRequest(t *testing.T) {
	tests := map[string]struct {
		SigningKeyID string
		SigningKey   []byte
		StoredKey    []byte
		StoredKeyErr error
		Claims       Claims
		ExpectedErr  string
	}{
		"SingleKey": {
			SigningKeyID: "abc123",
			SigningKey:   []byte("valid"),
			StoredKey:    []byte("valid"),
			Claims: Claims{
				Scopes: []Scope{{Permission: Read, Class: "stuff"}},
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: time.Now().Add(5 * time.Second).Unix(),
				},
			},
		},
		"MissingKeyID": {
			SigningKey:  []byte("test"),
			ExpectedErr: "token signed with unknown key",
		},
		"InvalidKeyID": {
			SigningKeyID: "abc123",
			SigningKey:   []byte("one thing"),
			StoredKeyErr: errors.New("no such key"),
			ExpectedErr:  "no such key",
		},
		"InvalidSignature": {
			SigningKeyID: "abc123",
			SigningKey:   []byte("one thing"),
			StoredKey:    []byte("another"),
			ExpectedErr:  "signature is invalid",
		},
		"ExpiredToken": {
			SigningKeyID: "abc123",
			SigningKey:   []byte("valid"),
			StoredKey:    []byte("valid"),
			Claims: Claims{
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: time.Now().Add(-5 * time.Second).Unix(),
				},
			},
			ExpectedErr: "token is expired by 5s",
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		ks := &mocks.KeyStore{}
		ks.On("KeyFromID", test.SigningKeyID).Return(test.StoredKey, test.StoredKeyErr)

		// Sign a fake token.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, test.Claims)
		if test.SigningKeyID != "" {
			token.Header["kid"] = test.SigningKeyID
		}
		signed, err := token.SignedString(test.SigningKey)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/", nil)
		req.Header.Set("Authorization", "Bearer "+signed)

		s := NewSigner(ks)
		claims, err := s.AuthRequest(req)
		if test.ExpectedErr != "" {
			assert.EqualError(t, err, test.ExpectedErr)
			continue
		}

		require.NoError(t, err)
		assert.Equal(t, test.Claims, *claims)
	}
}
