package main

import (
	"github.com/othonhugo/doubleratchet"
	"github.com/othonhugo/doubleratchet/crypto/ecdh"
)

func Setup() (doubleratchet.DoubleRatchet, doubleratchet.DoubleRatchet) {
	alicePri, _ := ecdh.GeneratePrivateKey()
	bobPri, _ := ecdh.GeneratePrivateKey()

	alice, err := doubleratchet.New(alicePri.Bytes(), bobPri.PublicKey().Bytes())

	if err != nil {
		panic(err)
	}

	bob, err := doubleratchet.New(bobPri.Bytes(), alicePri.PublicKey().Bytes())

	if err != nil {
		panic(err)
	}

	return alice, bob
}
