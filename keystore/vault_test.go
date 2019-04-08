package keystore

import (
	"crypto/rand"
	"fmt"
	mathRand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// First 100 hexadecimal characters from crypto/rand with a source seeded with zero.
const expected = "0194fdc2fa2ffcc041d3ff12045b73c86e4ff95ff662a5eee82abdf44a2d0b75fb180daf48a79ee0b10d394651850fd4a178"

func TestRandomHex(t *testing.T) {
	for i := 0; i <= len(expected); i++ {
		t.Run(fmt.Sprintf("Length%d", i), func(t *testing.T) {
			source := mathRand.NewSource(0)
			reader := mathRand.New(source)
			rand.Reader = reader
			actual, err := randomHex(i)
			require.NoError(t, err)
			assert.Equal(t, expected[:i], actual)
		})
	}
}
