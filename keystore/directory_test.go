package keystore

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectoryKeyStore(t *testing.T) {
	t.Run("DirectoryNotFound", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)
		ks, err := NewDirectoryKeyStore(path.Join(dir, "a"))
		assert.Nil(t, ks)
		assert.Error(t, err)
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		ks, err := NewDirectoryKeyStore(dir)
		require.NotNil(t, ks)
		require.NoError(t, err)

		actualKey, err := ks.KeyFromID("a")
		assert.Nil(t, actualKey)
		assert.Error(t, err)
	})

	t.Run("KeyFound", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		id := "a"
		key := []byte("abc")
		require.NoError(t, ioutil.WriteFile(path.Join(dir, id), key, 0644))

		ks, err := NewDirectoryKeyStore(dir)
		require.NotNil(t, ks)
		require.NoError(t, err)

		actualKey, err := ks.KeyFromID(id)
		assert.Equal(t, key, actualKey)
		assert.NoError(t, err)
	})

	t.Run("KeyAdded", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		id := "a"
		key := []byte("abc")

		ks, err := NewDirectoryKeyStore(dir)
		require.NotNil(t, ks)
		require.NoError(t, err)

		actualKey, err := ks.KeyFromID(id)
		require.Nil(t, actualKey)
		require.Error(t, err)

		require.NoError(t, ioutil.WriteFile(path.Join(dir, id), key, 0644))
		require.NoError(t, ks.Update())

		actualKey, err = ks.KeyFromID(id)
		assert.Equal(t, key, actualKey)
		assert.NoError(t, err)
	})

	t.Run("KeyRemoved", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		id := "a"
		key := []byte("abc")
		require.NoError(t, ioutil.WriteFile(path.Join(dir, id), key, 0644))

		ks, err := NewDirectoryKeyStore(dir)
		require.NotNil(t, ks)
		require.NoError(t, err)

		actualKey, err := ks.KeyFromID(id)
		require.Equal(t, key, actualKey)
		require.NoError(t, err)

		require.NoError(t, os.Remove(path.Join(dir, id)))
		require.NoError(t, ks.Update())

		actualKey, err = ks.KeyFromID(id)
		assert.Nil(t, actualKey)
		assert.Error(t, err)
	})

	t.Run("NopUpdate", func(t *testing.T) {
		dir, err := ioutil.TempDir("", "")
		require.NoError(t, err)

		id := "a"
		key := []byte("abc")
		require.NoError(t, ioutil.WriteFile(path.Join(dir, id), key, 0644))

		ks, err := NewDirectoryKeyStore(dir)
		require.NotNil(t, ks)
		require.NoError(t, err)

		actualKey, err := ks.KeyFromID(id)
		require.Equal(t, key, actualKey)
		require.NoError(t, err)

		require.NoError(t, ks.Update())

		actualKey, err = ks.KeyFromID(id)
		assert.Equal(t, key, actualKey)
		assert.NoError(t, err)
	})
}
