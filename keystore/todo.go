package keystore

import "errors"

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
