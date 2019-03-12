package keystore

import (
	"sync"
	"time"
)

//go:generate mockery -dir . -all

// KeyStore is an interface to retrieve signing keys by ID.
//
// Implementations are expected to produce stable keys, meaning a given key ID
// should always result in the same key or an error, even across processes.
type KeyStore interface {
	NewKey() (id string, key []byte, err error)
	KeyFromID(id string) ([]byte, error)
}

type cacheEntry struct {
	key       []byte
	refreshed time.Time
}

// Cache is a wrapped KeyStore with a simple TTL invalidation.
//
// This cache implementation assumes relatively small key sets and uses a naive
// in-memory map. Clients with larger key sets should use other solutions.
//
// Cache is safe for concurrent use if and only if
//     1. keys cannot change under the same ID.
//     2. the wrapped key store is safe for concurrent use.
type Cache struct {
	ks  KeyStore      // Wrapped key store
	ttl time.Duration // Time-to-live for each key

	lock    sync.RWMutex
	entries map[string]cacheEntry // Cached keys, indexed by ID
}

// WithCache wraps a key store with a cache. Each key accessed is cached with a
// time-to-live, after which keys will be re-validated upon access.
func WithCache(ks KeyStore, ttl time.Duration) *Cache {
	if ttl <= 0 {
		panic("time-to-live must be positive")
	}
	return &Cache{ks: ks, ttl: ttl, entries: map[string]cacheEntry{}}
}

// NewKey creates a key in the wrapped key store and caches the result on success.
//
// Callers must not modify the returned key.
func (c *Cache) NewKey() (id string, key []byte, err error) {
	id, key, err = c.ks.NewKey()
	if err == nil {
		c.store(id, key)
	}
	return
}

// KeyFromID retreives a key from the cache or, if the entry is absent or expired,
// retreives it from the underlying key store.
//
// Callers must not modify the returned key.
func (c *Cache) KeyFromID(id string) ([]byte, error) {
	if entry, ok := c.read(id); ok {
		return entry, nil
	}

	key, err := c.ks.KeyFromID(id)
	if err == nil {
		c.store(id, key)
	}
	return key, err
}

func (c *Cache) read(id string) (key []byte, ok bool) {
	c.lock.RLock()
	if entry, found := c.entries[id]; found && time.Since(entry.refreshed) < c.ttl {
		key, ok = entry.key, true
	}
	c.lock.RUnlock()
	return
}

func (c *Cache) store(id string, key []byte) {
	c.lock.Lock()
	c.entries[id] = cacheEntry{key, time.Now()}
	c.lock.Unlock()
}
