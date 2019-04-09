package keystore

import (
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

// WriteKey writes a key to Vault. Returns an error if a key with the
// given ID already exists.
func (ks *VaultKeyStore) WriteKey(id string, key []byte) error {
	secret, err := ks.client.Logical().Read(ks.secretPath)
	if err != nil {
		return errors.WithStack(err)
	}
	if _, ok := secret.Data[id]; ok {
		return errors.New("key collision")
	}

	secret.Data[id] = key
	if _, err := ks.client.Logical().Write(ks.secretPath, secret.Data); err != nil {
		return errors.WithStack(err)
	}
	return nil
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
