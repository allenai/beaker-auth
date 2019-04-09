package keystore

import (
	"github.com/pkg/errors"
)

type MemoryKeyStore struct {
	keys map[string][]byte
}

// NewMemoryKeyStore create a new in-memory key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys: make(map[string][]byte),
	}
}

func (ks *MemoryKeyStore) WriteKey(id string, key []byte) error {
	if _, ok := ks.keys[id]; ok {
		return errors.New("key collision")
	}
	ks.keys[id] = key
	return nil
}

func (ks *MemoryKeyStore) KeyFromID(id string) ([]byte, error) {
	key, ok := ks.keys[id]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}
