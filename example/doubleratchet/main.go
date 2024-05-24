package main

import "fmt"

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
