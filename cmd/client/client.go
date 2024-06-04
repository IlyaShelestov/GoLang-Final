package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	CONN_PORT = ":9090"
	CONN_TYPE = "tcp"
)

var (
	hexKey           = "d282a02a534d7be5b777b592227bdc3fa1ee8bedf853e129d17db9976817adab"
	encryptionKey, _ = hex.DecodeString(hexKey)
)

func encryptMessage(plainText string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decryptMessage(cipherText string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("cipherText too short")
	}

	nonce, cipherTextBytes := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func readFromServer(conn net.Conn) {
	for {
		message, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			fmt.Println("Disconnected from the server.")
			return
		}
		decryptedMessage, err := decryptMessage(strings.TrimSpace(message))
		if err != nil {
			fmt.Println("Error decrypting message:", err)
			continue
		}
		fmt.Print("Server: ", decryptedMessage)
	}
}

func writeToServer(conn net.Conn) {
	consoleReader := bufio.NewReader(os.Stdin)
	for {
		input, _ := consoleReader.ReadString('\n')
		trimmedInput := strings.TrimSpace(input)
		if trimmedInput == "/quit" {
			fmt.Println("Disconnecting from server...")
			conn.Write([]byte("/quit\n"))
			conn.Close()
			os.Exit(0)
		}
		encryptedInput, err := encryptMessage(trimmedInput)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			continue
		}
		conn.Write([]byte(encryptedInput + "\n"))
	}
}

func main() {
	conn, err := net.Dial(CONN_TYPE, CONN_PORT)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		os.Exit(1)
	}

	fmt.Print("Enter your nickname: ")
	nicknameReader := bufio.NewReader(os.Stdin)
	nickname, _ := nicknameReader.ReadString('\n')
	nickname = strings.TrimSpace(nickname)
	encryptedNickname, err := encryptMessage("/nickname " + nickname)
	if err != nil {
		fmt.Println("Error encrypting nickname:", err)
		os.Exit(1)
	}
	conn.Write([]byte(encryptedNickname + "\n"))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readFromServer(conn)
	}()

	writeToServer(conn)

	wg.Wait()
}
