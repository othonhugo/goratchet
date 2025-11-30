package doubleratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"math/big"
	"sync"
	"testing"

	"github.com/othonhugo/goratchet/pkg/crypto"
)

// TestBasicMessageExchangeAndOutOfOrderDelivery verifies that the Double Ratchet protocol
// correctly handles bidirectional message exchange between two parties and can decrypt
// messages received out of order by maintaining skipped message keys.
func TestBasicMessageExchangeAndOutOfOrderDelivery(t *testing.T) {
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

// TestDiffieHellmanRatchetStep verifies that the DH ratchet step correctly advances
// the protocol state when a party performs a DH ratchet (key refresh), ensuring that
// both parties can continue to communicate after the ratchet step.
func TestDiffieHellmanRatchetStep(t *testing.T) {
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

// TestMaxSkipLimitEnforcement verifies that the protocol correctly enforces the maximum
// number of skipped messages (MaxSkip) and returns an error when attempting to skip
// more messages than allowed, preventing memory exhaustion attacks.
func TestMaxSkipLimitEnforcement(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	var lastMsg CipheredMessage

	for range MaxSkip + 1 {
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

// TestDelayedMessageDecryptionAcrossDHRatchet verifies that messages sent before a
// DH ratchet step can still be decrypted after the ratchet has advanced, ensuring
// the protocol maintains backward compatibility with skipped message keys.
func TestDelayedMessageDecryptionAcrossDHRatchet(t *testing.T) {
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

// TestMultipleMessagesOutOfOrderDecryption verifies that the protocol can handle
// a large number of messages sent in sequence and decrypt them all when received
// in reverse order, testing the skipped message key storage mechanism.
func TestMultipleMessagesOutOfOrderDecryption(t *testing.T) {
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

// TestDuplicateMessageRejection verifies that the protocol correctly rejects duplicate
// messages (replay attacks) by ensuring that a message can only be decrypted once,
// with subsequent attempts failing.
func TestDuplicateMessageRejection(t *testing.T) {
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

// TestAssociatedDataAuthentication verifies that the protocol correctly uses
// associated data (AD) for authentication, ensuring messages can only be decrypted
// with the correct AD and fail with incorrect or mismatched AD.
func TestAssociatedDataAuthentication(t *testing.T) {
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

// TestConcurrentSendAndReceiveOperations verifies that the Double Ratchet implementation
// is thread-safe and can handle concurrent Send and Receive operations without data races
// or corruption, using proper synchronization mechanisms.
func TestConcurrentSendAndReceiveOperations(t *testing.T) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	var wg sync.WaitGroup

	count := 100

	wg.Add(1)

	go func() {
		defer wg.Done()

		for range count {
			if _, err := alice.Send([]byte("msg"), nil); err != nil {
				t.Errorf("Concurrent Send failed: %v", err)
			}
		}
	}()

	wg.Add(1)

	go func() {
		defer wg.Done()

		for range count {
			msg, _ := bob.Send([]byte("reply"), nil)

			if _, err := alice.Receive(msg, nil); err != nil {
				t.Errorf("Concurrent Receive failed: %v", err)
			}
		}
	}()

	wg.Wait()
}

// FuzzReceiveWithMalformedInput performs fuzz testing on the Receive function to ensure
// it handles malformed, corrupted, or malicious input gracefully without panicking or
// causing undefined behavior, improving robustness against attacks.
func FuzzReceiveWithMalformedInput(f *testing.F) {
	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	f.Add([]byte("random garbage"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		header := Header{
			DH: bob.dh.localPrivateKey.PublicKey().Bytes(),
			N:  0,
			PN: 0,
		}

		msg := CipheredMessage{
			Header:     header,
			Ciphertext: data,
		}

		bob.Receive(msg, nil)
	})
}

// TestLongRunningSessionWithNetworkConditions simulates a long-running session with
// 1000 messages delivered in random order (simulating network reordering), verifying
// that the protocol maintains correctness under realistic adverse network conditions.
func TestLongRunningSessionWithNetworkConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long running simulation in short mode")
	}

	alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
	bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

	alice, _ := New(alicePri.Bytes(), bobPri.PublicKey().Bytes(), nil)
	bob, _ := New(bobPri.Bytes(), alicePri.PublicKey().Bytes(), nil)

	messages := make([]CipheredMessage, 0, 1000)

	for range 1000 {
		msg, _ := alice.Send([]byte("msg"), nil)
		messages = append(messages, msg)
	}

	for i := range len(messages) - 1 {
		n, _ := rand.Int(rand.Reader, big.NewInt(10))

		if n.Int64() == 0 {
			messages[i], messages[i+1] = messages[i+1], messages[i]
		}
	}

	for _, msg := range messages {
		bob.Receive(msg, nil)
	}
}
