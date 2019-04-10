package keystore

import (
	"bytes"
	"io/ioutil"
	"path"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

type DirectoryKeyStore struct {
	path string
	keys map[string][]byte
	lock sync.RWMutex
}

// NewDirectoryKeyStore creates a key store from a directory.
// Each file in the directory is a key. The name of the file
// is the ID of the key and its contents are the key.
func NewDirectoryKeyStore(path string) (*DirectoryKeyStore, error) {
	ks := &DirectoryKeyStore{
		path: path,
		keys: make(map[string][]byte),
	}
	if err := ks.Update(); err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *DirectoryKeyStore) KeyFromID(id string) ([]byte, error) {
	ks.lock.RLock()
	defer ks.lock.RUnlock()

	key, ok := ks.keys[id]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// Update keys from disk.
func (ks *DirectoryKeyStore) Update() error {
	files, err := ioutil.ReadDir(ks.path)
	if err != nil {
		return errors.WithStack(err)
	}

	keys := make(map[string][]byte)
	for _, info := range files {
		if info.IsDir() || strings.HasPrefix(info.Name(), ".") {
			continue
		}

		id := info.Name()
		if _, ok := ks.keys[id]; !ok {
			key, err := ioutil.ReadFile(path.Join(ks.path, id))
			if err != nil {
				return errors.WithStack(err)
			}
			keys[id] = bytes.TrimSpace(key)
		}
	}

	ks.lock.Lock()
	defer ks.lock.Unlock()
	ks.keys = keys
	return nil
}
