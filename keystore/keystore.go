package keystore

//go:generate mockery -dir . -all

// KeyStore is an interface to retrieve signing keys by ID.
//
// Implementations are expected to produce stable keys, meaning a given key ID
// should always result in the same key or an error, even across processes.
type KeyStore interface {
	KeyFromID(id string) ([]byte, error)
}
