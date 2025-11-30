// nolint:all // Example code: focus on clarity over style
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/othonhugo/goratchet"
)

var message = []byte("hello, there!")

func main() {
	alice, bob := setup()

	ciphered, err := alice.Send(message, nil)

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

func setup() (goratchet.DoubleRatchet, goratchet.DoubleRatchet) {
	alicePri, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		panic(err)
	}

	bobPri, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		panic(err)
	}

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
