package doubleratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestSerialization(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	msg1, _ := alice.Send([]byte("msg1"), nil)
	bob.Receive(msg1, nil)

	data, err := alice.Serialize()

	if err != nil {
		t.Fatalf("Serialization failed: %v", err)
	}

	aliceRestored, err := Deserialize(data)

	if err != nil {
		t.Fatalf("Deserialization failed: %v", err)
	}

	msg2, _ := aliceRestored.Send([]byte("msg2"), nil)
	decrypted, err := bob.Receive(msg2, nil)

	if err != nil {
		t.Fatalf("Failed to receive from restored session: %v", err)
	}

	if string(decrypted.Plaintext) != "msg2" {
		t.Errorf("Expected 'msg2', got '%s'", decrypted.Plaintext)
	}
}
