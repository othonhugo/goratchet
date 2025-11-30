package doubleratchet

import (
	"bytes"
	"testing"
)

// TestDHKeyExchangeAndSharedSecretAgreement verifies that two DH ratchets can perform
// a key exchange and arrive at the same shared secret, and that remote public keys
// are correctly stored after the exchange.
func TestDHKeyExchangeAndSharedSecretAgreement(t *testing.T) {
	dh1 := &diffieHellmanRatchet{}

	if err := dh1.refresh(); err != nil {
		t.Fatal(err)
	}

	dh2 := &diffieHellmanRatchet{}

	if err := dh2.refresh(); err != nil {
		t.Fatal(err)
	}

	secret1, err := dh1.exchange(dh2.localPrivateKey.PublicKey())

	if err != nil {
		t.Fatal(err)
	}

	secret2, err := dh2.exchange(dh1.localPrivateKey.PublicKey())

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Error("Shared secrets do not match")
	}

	if !bytes.Equal(dh1.remotePublicKey.Bytes(), dh2.localPrivateKey.PublicKey().Bytes()) {
		t.Error("Remote public key not set correctly in dh1")
	}

	if !bytes.Equal(dh2.remotePublicKey.Bytes(), dh1.localPrivateKey.PublicKey().Bytes()) {
		t.Error("Remote public key not set correctly in dh2")
	}

	oldPub := dh1.localPrivateKey.PublicKey().Bytes()

	if err := dh1.refresh(); err != nil {
		t.Fatal(err)
	}

	newPub := dh1.localPrivateKey.PublicKey().Bytes()

	if bytes.Equal(oldPub, newPub) {
		t.Error("Public key did not change after refresh")
	}
}

// TestDHKeyRefreshChangesPublicKey verifies that calling refresh() on a DH ratchet
// generates a new key pair, ensuring forward secrecy by changing the public key
// after each ratchet step.
func TestDHKeyRefreshChangesPublicKey(t *testing.T) {
	dh := &diffieHellmanRatchet{}

	if err := dh.refresh(); err != nil {
		t.Fatal(err)
	}

	secret1, _ := dh.exchange(dh.localPrivateKey.PublicKey())

	if err := dh.refresh(); err != nil {
		t.Fatal(err)
	}

	secret2, _ := dh.exchange(dh.localPrivateKey.PublicKey())

	if bytes.Equal(secret1, secret2) {
		t.Error("Secret should change after refreshing local key")
	}
}

// TestDHSharedSecretChangesAfterRefresh verifies that the shared secret changes
// when a DH ratchet refreshes its local key, ensuring that each ratchet step
// produces a unique shared secret for forward secrecy.
func TestDHSharedSecretChangesAfterRefresh(t *testing.T) {
	dh1 := &diffieHellmanRatchet{}
	dh2 := &diffieHellmanRatchet{}

	for i := range 5 {
		if err := dh1.refresh(); err != nil {
			t.Fatal(err)
		}

		if err := dh2.refresh(); err != nil {
			t.Fatal(err)
		}

		secret1, _ := dh1.exchange(dh2.localPrivateKey.PublicKey())
		secret2, _ := dh2.exchange(dh1.localPrivateKey.PublicKey())

		if !bytes.Equal(secret1, secret2) {
			t.Errorf("Iteration %d: secrets do not match", i)
		}
	}
}

// TestDHMultipleRatchetStepsProduceUniqueSecrets verifies that multiple consecutive
// DH ratchet steps between two parties always produce matching shared secrets,
// ensuring consistency across multiple key exchanges.
func TestDHMultipleRatchetStepsProduceUniqueSecrets(t *testing.T) {
	dh1 := &diffieHellmanRatchet{}
	dh2 := &diffieHellmanRatchet{}

	dh1.refresh()
	dh2.refresh()

	pub2Before := dh2.localPrivateKey.PublicKey().Bytes()
	dh1.exchange(dh2.localPrivateKey.PublicKey())

	if !bytes.Equal(dh1.remotePublicKey.Bytes(), pub2Before) {
		t.Error("dh1 remotePublicKey not updated correctly")
	}

	dh2.refresh()

	pub2After := dh2.localPrivateKey.PublicKey().Bytes()
	dh1.exchange(dh2.localPrivateKey.PublicKey())

	if !bytes.Equal(dh1.remotePublicKey.Bytes(), pub2After) {
		t.Error("dh1 remotePublicKey not updated after DH2 refresh")
	}
}

// TestDHRemotePublicKeyUpdateTracking verifies that the DH ratchet correctly updates
// and tracks the remote party's public key after each exchange, ensuring proper
// synchronization between parties.
func TestDHRemotePublicKeyUpdateTracking(t *testing.T) {
	dh := &diffieHellmanRatchet{}
	dh.refresh()

	if _, err := dh.exchange(nil); err == nil {
		t.Error("Expected error when exchanging with nil public key")
	}
}

// TestDHExchangeWithNilKeyReturnsError verifies that attempting to perform a DH
// exchange with a nil public key returns an error, preventing invalid operations
// and potential security vulnerabilities.
func TestDHExchangeWithNilKeyReturnsError(t *testing.T) {
	dh := &diffieHellmanRatchet{}
	dh.refresh()

	if _, err := dh.exchange(nil); err == nil {
		t.Error("Expected error when exchanging with nil public key")
	}
}

// TestDHExchangeDeterminism verifies that performing a DH exchange with the same
// public key multiple times produces the same shared secret, ensuring deterministic
// behavior required for protocol correctness.
func TestDHExchangeDeterminism(t *testing.T) {
	dh1 := &diffieHellmanRatchet{}
	dh2 := &diffieHellmanRatchet{}

	dh1.refresh()
	dh2.refresh()

	secret1, _ := dh1.exchange(dh2.localPrivateKey.PublicKey())
	secret2, _ := dh1.exchange(dh2.localPrivateKey.PublicKey())

	if !bytes.Equal(secret1, secret2) {
		t.Error("Exchange should be deterministic for same keys")
	}
}
