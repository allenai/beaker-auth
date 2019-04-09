package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	id, err := randomHex(4)
	if err != nil {
		panic(err)
	}

	key, err := randomHex(32)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ID:  %s\nKey: %s\n", id, key)
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, (n+1)/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes)[:n], nil
}
