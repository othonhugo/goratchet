package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/othonhugo/goratchet"
)

var Message = []byte("hello, there!")

func main() {
	alice, bob := Setup()

	ciphered, err := alice.Send(Message, nil)

	if err != nil {
		panic(err)
	}

	unciphered, err := bob.Receive(ciphered, nil)

	if err != nil {
		panic(err)
	}

	fmt.Printf("Ciphertext: %2X\n", ciphered.Ciphertext)
	fmt.Printf("Plaintext: %s\n", unciphered.Plaintext)
}

func Setup() (goratchet.DoubleRatchet, goratchet.DoubleRatchet) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, err := goratchet.New(alicePri.Bytes(), bobPri.PublicKey().Bytes())

	if err != nil {
		panic(err)
	}

	bob, err := goratchet.New(bobPri.Bytes(), alicePri.PublicKey().Bytes())

	if err != nil {
		panic(err)
	}

	return alice, bob
}
