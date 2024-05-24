package main

import (
	"fmt"

	"github.com/othonhugo/doubleratchet"
	"github.com/othonhugo/doubleratchet/crypto/ecdh"
)

var Message = []byte("hello, there!")

func main() {
	alice, bob := Setup()

	ciphered, err := alice.Send(Message, nil)

	if err != nil {
		panic(err)
	}

	unciphered, err := bob.Receive(ciphered)

	if err != nil {
		panic(err)
	}

	fmt.Printf("Ciphertext: %2X\n", ciphered.Ciphertext)
	fmt.Printf("Plaintext: %s\n", unciphered.Plaintext)
}

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
