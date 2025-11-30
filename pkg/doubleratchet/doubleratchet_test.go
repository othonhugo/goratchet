package doubleratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/othonhugo/doubleratchet/pkg/crypto"
)

func TestDoubleRatchet(t *testing.T) {
	alicePri, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		t.Fatal(err)
	}

	bobPri, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		t.Fatal(err)
	}

	alice, err := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)

	if err != nil {
		t.Fatal(err)
	}

	bob, err := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	if err != nil {
		t.Fatal(err)
	}

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

	msg3, _ := alice.Send([]byte("Msg 1"), nil)
	msg4, _ := alice.Send([]byte("Msg 2"), nil)
	msg5, _ := alice.Send([]byte("Msg 3"), nil)

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

func TestRatchetStep(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, err := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)

	if err != nil {
		t.Fatal(err)
	}

	bob, err := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	if err != nil {
		t.Fatal(err)
	}

	msg1, err := alice.Send([]byte("Msg 1"), nil)

	if err != nil {
		t.Fatal(err)
	}

	if _, err := bob.Receive(msg1, nil); err != nil {
		t.Fatal(err)
	}

	if err := alice.dh.refresh(); err != nil {
		t.Fatal(err)
	}

	dhOut, err := alice.dh.exchange(alice.dh.remotePublicKey)

	if err != nil {
		t.Fatal(err)
	}

	alice.rootKey, alice.sendChainKey = crypto.DeriveRK(alice.rootKey, dhOut)

	alice.prevN = alice.sendN
	alice.sendN = 0

	msg2, err := alice.Send([]byte("Msg 2 (New Key)"), nil)

	if err != nil {
		t.Fatal(err)
	}

	decrypted2, err := bob.Receive(msg2, nil)

	if err != nil {
		t.Fatalf("Bob failed to receive ratcheted message: %v", err)
	}

	if string(decrypted2.Plaintext) != "Msg 2 (New Key)" {
		t.Errorf("Expected 'Msg 2 (New Key)', got '%s'", decrypted2.Plaintext)
	}

	msg3, err := bob.Send([]byte("Msg 3 (Reply)"), nil)

	if err != nil {
		t.Fatal(err)
	}

	decrypted3, err := alice.Receive(msg3, nil)

	if err != nil {
		t.Fatalf("Alice failed to receive reply: %v", err)
	}

	if string(decrypted3.Plaintext) != "Msg 3 (Reply)" {
		t.Errorf("Expected 'Msg 3 (Reply)', got '%s'", decrypted3.Plaintext)
	}
}

func TestMaxSkip(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	var lastMsg CipheredMessage

	for i := 0; i <= MaxSkip+1; i++ {
		msg, _ := alice.Send([]byte("skip"), nil)
		lastMsg = msg
	}

	_, err := bob.Receive(lastMsg, nil)

	if err == nil {
		t.Fatal("Expected error due to too many skipped messages, got nil")
	}

	if err.Error() != "too many skipped messages" {
		t.Errorf("Expected 'too many skipped messages', got '%v'", err)
	}
}

func TestDelayedMessageAcrossRatchet(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	msgA1, _ := alice.Send([]byte("A1"), nil)

	bob.Receive(msgA1, nil)

	msgA2, _ := alice.Send([]byte("A2"), nil)

	alice.dh.refresh()

	dhOut, _ := alice.dh.exchange(alice.dh.remotePublicKey)
	alice.rootKey, alice.sendChainKey = crypto.DeriveRK(alice.rootKey, dhOut)

	alice.prevN = alice.sendN
	alice.sendN = 0

	msgB1, _ := alice.Send([]byte("B1"), nil)

	decryptedB1, err := bob.Receive(msgB1, nil)

	if err != nil {
		t.Fatalf("Bob failed to receive B1: %v", err)
	}

	if string(decryptedB1.Plaintext) != "B1" {
		t.Errorf("Expected B1, got %s", decryptedB1.Plaintext)
	}

	decryptedA2, err := bob.Receive(msgA2, nil)

	if err != nil {
		t.Fatalf("Bob failed to receive A2: %v", err)
	}

	if string(decryptedA2.Plaintext) != "A2" {
		t.Errorf("Expected A2, got %s", decryptedA2.Plaintext)
	}
}

func TestDoubleRatchetMultipleMessages(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	const n = 50

	messages := make([]CipheredMessage, n)

	for i := range n {
		msg := []byte("Message " + string(rune(i)))
		messages[i], _ = alice.Send(msg, nil)
	}

	for i := n - 1; i >= 0; i-- {
		decrypted, err := bob.Receive(messages[i], nil)

		if err != nil {
			t.Fatalf("Failed to receive message %d: %v", i, err)
		}

		expected := "Message " + string(rune(i))

		if string(decrypted.Plaintext) != expected {
			t.Fatalf("Expected '%s', got '%s'", expected, decrypted.Plaintext)
		}
	}
}

func TestDoubleRatchetDuplicateMessages(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	msg, _ := alice.Send([]byte("Hello"), nil)

	_, err := bob.Receive(msg, nil)

	if err != nil {
		t.Fatal(err)
	}

	_, err = bob.Receive(msg, nil)

	if err == nil {
		t.Error("Expected error on duplicate message, got nil")
	}
}

func TestDoubleRatchetWithAD(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	ad := []byte("context")
	msg, _ := alice.Send([]byte("Secure"), ad)

	decrypted, err := bob.Receive(msg, ad)

	if err != nil || string(decrypted.Plaintext) != "Secure" {
		t.Fatal("Failed to decrypt with correct AD")
	}

	_, err = bob.Receive(msg, []byte("wrong"))

	if err == nil {
		t.Error("Expected error with incorrect AD, got nil")
	}
}
