package ecdh

import (
	"crypto/ecdh"
	"crypto/rand"
)

func GeneratePrivateKey() (*PrivateKey, error) {
	return ecdh.P521().GenerateKey(rand.Reader)
}

func UnmarshalPublicKey(pub []byte) (*PublicKey, error) {
	return ecdh.P521().NewPublicKey(pub)
}

func UnmarshalPrivateKey(pri []byte) (*PrivateKey, error) {
	return ecdh.P521().NewPrivateKey(pri)
}
