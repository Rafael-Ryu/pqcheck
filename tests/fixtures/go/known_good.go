package main

import (
	"crypto/aes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	aes.NewCipher(key)
	sha256.New()
	mlkem.GenerateKey768()
	chacha20poly1305.New(key)
	rand.Read(buf)
}
