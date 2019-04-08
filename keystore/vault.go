package keystore

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

type VaultKeyStore struct {
	client     *api.Client
	secretPath string
}

// NewVaultKeyStore creates a key store backed by the Vault instance
// at the given address. A token is required to authenticate with Vault.
// Secrets are stored under the given prefix e.g. secret/my/secrets.
func NewVaultKeyStore(address, token, secretPath string) (*VaultKeyStore, error) {
	client, err := api.NewClient(&api.Config{Address: address})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	client.SetToken(token)
	return &VaultKeyStore{client: client, secretPath: secretPath}, nil
}

// NewKey generates a random key and stores it in Vault.
func (ks *VaultKeyStore) NewKey() (id string, key []byte, err error) {
	id, err = randomHex(4)
	if err != nil {
		return "", nil, err
	}

	k, err := randomHex(32)
	if err != nil {
		return "", nil, err
	}
	key = []byte(k)

	secret, err := ks.client.Logical().Read(ks.secretPath)
	if err != nil {
		return "", nil, errors.WithStack(err)
	}
	if _, ok := secret.Data[id]; ok {
		// Key collision; try a new key.
		return ks.NewKey()
	}

	secret.Data[id] = key
	if _, err := ks.client.Logical().Write(ks.secretPath, secret.Data); err != nil {
		return "", nil, errors.WithStack(err)
	}

	return id, key, nil
}

// KeyFromID looks up a key by its ID and returns an undefined error
// if a key does not exist with the given ID.
func (ks *VaultKeyStore) KeyFromID(id string) ([]byte, error) {
	secret, err := ks.client.Logical().Read(ks.secretPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	keySecret, ok := secret.Data[id]
	if !ok {
		return nil, errors.New("key not found")
	}
	key, ok := keySecret.([]byte)
	if !ok {
		return nil, errors.New("key is not []byte")
	}
	return key, nil
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, (n+1)/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:n], nil
}
