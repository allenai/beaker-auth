package keystore

import (
	"errors"
	"testing"
	"time"

	"github.com/allenai/beaker-auth/keystore/mocks"
	"github.com/stretchr/testify/assert"
)

const testKeyID = "foo"

var testKey = []byte("secret")

func TestCacheNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		ks := &mocks.KeyStore{}
		ks.On("NewKey").Return(testKeyID, testKey, nil).Once()
		cache := WithCache(ks, time.Minute)

		id, k, err := cache.NewKey()
		assert.Equal(t, testKeyID, id)
		assert.Equal(t, testKey, k)
		assert.NoError(t, err)
		k, err = cache.KeyFromID(testKeyID)
		assert.Equal(t, testKey, k)
		assert.NoError(t, err)

		ks.AssertExpectations(t)
	})

	// Failed keys should not be stored.
	t.Run("Failure", func(t *testing.T) {
		ks := &mocks.KeyStore{}
		ks.On("NewKey").Return("", nil, errors.New("no luck")).Once()
		cache := WithCache(ks, time.Minute)

		id, k, err := cache.NewKey()
		assert.Zero(t, id)
		assert.Nil(t, k)
		assert.EqualError(t, err, "no luck")

		ks.AssertExpectations(t)
	})

}

func TestCacheHit(t *testing.T) {
	ks := &mocks.KeyStore{}
	ks.On("KeyFromID", testKeyID).Return(testKey, nil).Once()
	cache := WithCache(ks, time.Minute)

	k, err := cache.KeyFromID(testKeyID)
	assert.Equal(t, testKey, k)
	assert.NoError(t, err)
	k, err = cache.KeyFromID(testKeyID)
	assert.Equal(t, testKey, k)
	assert.NoError(t, err)

	ks.AssertExpectations(t)
}

func TestCacheError(t *testing.T) {
	ks := &mocks.KeyStore{}
	ks.On("KeyFromID", testKeyID).Return(nil, errors.New("no such key")).Twice()
	cache := WithCache(ks, time.Minute)

	k, err := cache.KeyFromID(testKeyID)
	assert.Nil(t, k)
	assert.EqualError(t, err, "no such key")
	k, err = cache.KeyFromID(testKeyID)
	assert.Nil(t, k)
	assert.EqualError(t, err, "no such key")

	ks.AssertExpectations(t)
}

func TestCacheExpire(t *testing.T) {
	ks := &mocks.KeyStore{}
	ks.On("KeyFromID", testKeyID).Return(testKey, nil).Twice()
	cache := WithCache(ks, time.Nanosecond)

	k, err := cache.KeyFromID(testKeyID)
	assert.Equal(t, testKey, k)
	assert.NoError(t, err)
	time.Sleep(time.Millisecond)
	k, err = cache.KeyFromID(testKeyID)
	assert.Equal(t, testKey, k)
	assert.NoError(t, err)

	ks.AssertExpectations(t)
}
