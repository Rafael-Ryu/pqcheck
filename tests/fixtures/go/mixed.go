package main

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func main() {
	rsa.GenerateKey(rand.Reader, 4096)
	aes.NewCipher(key)
	sha256.Sum256(data)
	md5.Sum(data)
}
