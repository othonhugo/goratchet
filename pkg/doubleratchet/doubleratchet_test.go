package doubleratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestDoubleRatchet(t *testing.T) {
	// Setup Alice and Bob
	alicePri, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPri, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	alice, err := New(alicePri.Bytes(), bobPri.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	bob, err := New(bobPri.Bytes(), alicePri.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// 1. Alice sends to Bob
	msg1, err := alice.Send([]byte("Hello Bob"), nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted1, err := bob.Receive(msg1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted1.Plaintext) != "Hello Bob" {
		t.Fatalf("Expected 'Hello Bob', got '%s'", decrypted1.Plaintext)
	}

	// 2. Bob sends to Alice
	msg2, err := bob.Send([]byte("Hello Alice"), nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted2, err := alice.Receive(msg2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted2.Plaintext) != "Hello Alice" {
		t.Fatalf("Expected 'Hello Alice', got '%s'", decrypted2.Plaintext)
	}

	// 3. Out of order
	// Alice sends 3 messages
	msg3, _ := alice.Send([]byte("Msg 1"), nil)
	msg4, _ := alice.Send([]byte("Msg 2"), nil)
	msg5, _ := alice.Send([]byte("Msg 3"), nil)

	// Bob receives 3, then 1, then 2
	decrypted5, err := bob.Receive(msg5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted5.Plaintext) != "Msg 3" {
		t.Fatalf("Expected 'Msg 3', got '%s'", decrypted5.Plaintext)
	}

	decrypted3, err := bob.Receive(msg3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted3.Plaintext) != "Msg 1" {
		t.Fatalf("Expected 'Msg 1', got '%s'", decrypted3.Plaintext)
	}

	decrypted4, err := bob.Receive(msg4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted4.Plaintext) != "Msg 2" {
		t.Fatalf("Expected 'Msg 2', got '%s'", decrypted4.Plaintext)
	}
}
