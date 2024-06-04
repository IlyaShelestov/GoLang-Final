package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func generateEncryptionKey() (string, error) {
	key := make([]byte, 32) // 32 bytes = 256 bits
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

func main() {
	key, err := generateEncryptionKey()
	if err != nil {
		fmt.Println("Error generating encryption key:", err)
		return
	}
	fmt.Println("Encryption Key:", key)
}
