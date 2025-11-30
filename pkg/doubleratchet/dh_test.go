package doubleratchet

import (
	"bytes"
	"testing"
)

func TestDiffieHellmanRatchet(t *testing.T) {
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

func TestExchangeChangesAfterRefresh(t *testing.T) {
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

func TestRepeatedExchanges(t *testing.T) {
	dh1 := &diffieHellmanRatchet{}
	dh2 := &diffieHellmanRatchet{}

	for i := 0; i < 5; i++ {
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

func TestRemotePublicKeyUpdate(t *testing.T) {
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

func TestExchangeWithNilKey(t *testing.T) {
	dh := &diffieHellmanRatchet{}
	dh.refresh()

	if _, err := dh.exchange(nil); err == nil {
		t.Error("Expected error when exchanging with nil public key")
	}
}

func TestDeterministicExchange(t *testing.T) {
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
