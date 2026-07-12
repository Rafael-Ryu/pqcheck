package main

import (
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"golang.org/x/crypto/curve25519"
)

func main() {
	md5.New()
	sha1.New()
	rsa.GenerateKey(rand.Reader, 2048)
	ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	des.NewCipher(key)
	rc4.NewCipher(key)
	ed25519.GenerateKey(rand.Reader)
	ecdh.X25519()
	elliptic.P384()
	curve25519.X25519(scalar, point)
}
