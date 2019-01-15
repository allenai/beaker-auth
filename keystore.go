package auth

import "errors"

//go:generate mockery -inpkg -testonly -dir . -all

// KeyStore is an interface to retrieve signing keys by ID.
//
// Implementations are expected to produce stable keys, meaning a given key ID
// should always result in the same key or an error, even across processes.
type KeyStore interface {
	NewKey() (id string, key []byte, err error)
	KeyFromID(id string) ([]byte, error)
}

// TODO: Only here temporarily; remove when real key stores are in place.
type KeyStoreTODO struct {
	KeyID string
	Key   string
}

func (ks *KeyStoreTODO) NewKey() (id string, key []byte, err error) {
	return ks.KeyID, []byte(ks.Key), nil
}

func (ks *KeyStoreTODO) KeyFromID(id string) ([]byte, error) {
	if id != ks.KeyID {
		return nil, errors.New("signing key is invalid or expired")
	}
	return []byte(ks.Key), nil
}
