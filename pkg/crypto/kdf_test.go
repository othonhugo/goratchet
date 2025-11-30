package crypto

import (
	"bytes"
	"testing"
)

// TestHKDFBasicDerivation verifies that the HKDF key derivation function correctly
// derives keys of the specified length from a secret, salt, and info, including
// handling of nil salt values.
func TestHKDFBasicDerivation(t *testing.T) {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")
	length := 32

	out := DeriveHKDF(secret, salt, info, length)

	if len(out) != length {
		t.Errorf("Expected length %d, got %d", length, len(out))
	}

	// Test with nil salt
	out2 := DeriveHKDF(secret, nil, info, length)

	if len(out2) != length {
		t.Errorf("Expected length %d, got %d", length, len(out2))
	}
}

// TestRootKeyDerivation verifies that the DeriveRK function correctly derives a new
// root key and chain key from the current root key and DH output, ensuring both
// derived keys are different from the input root key.
func TestRootKeyDerivation(t *testing.T) {
	var rk ChainKey

	copy(rk[:], []byte("rootkey0123456789012345678901234"))

	dhOut := []byte("dhoutput")

	nextRk, nextCk := DeriveRK(rk, dhOut)

	if nextRk == rk {
		t.Error("Next Root Key should be different")
	}
	if nextCk == rk {
		t.Error("Next Chain Key should be different")
	}
}

// TestChainKeyDerivation verifies that the DeriveCK function correctly derives a new
// chain key and message key from the current chain key, ensuring both derived keys
// are different from the input and non-zero.
func TestChainKeyDerivation(t *testing.T) {
	var ck ChainKey

	copy(ck[:], []byte("chainkey012345678901234567890123"))

	nextCk, mk := DeriveCK(ck)

	if nextCk == ck {
		t.Error("Next Chain Key should be different")
	}

	// Check that mk is not zero
	zeroMk := MessageKey{}

	if mk == zeroMk {
		t.Error("Message Key should not be zero")
	}
}

// TestHKDFOutputLengthVariations verifies that the HKDF function can produce outputs
// of various lengths from 0 to 128 bytes, ensuring flexibility in key derivation
// for different cryptographic purposes.
func TestHKDFOutputLengthVariations(t *testing.T) {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")

	lengths := []int{0, 1, 16, 32, 64, 128}

	for _, l := range lengths {
		out := DeriveHKDF(secret, salt, info, l)

		if len(out) != l {
			t.Errorf("Expected length %d, got %d", l, len(out))
		}
	}
}

// TestHKDFNilAndEmptySaltEquivalence verifies that HKDF treats nil salt and empty
// salt as equivalent, producing the same output for both cases, ensuring consistent
// behavior across different salt representations.
func TestHKDFNilAndEmptySaltEquivalence(t *testing.T) {
	secret := []byte("secret")
	info := []byte("info")
	length := 32

	out1 := DeriveHKDF(secret, nil, info, length)
	out2 := DeriveHKDF(secret, []byte{}, info, length)

	if !bytes.Equal(out1, out2) {
		t.Errorf("Expected nil and empty salt to produce same output")
	}
}

// TestRootKeyDerivationUniqueness verifies that different DH outputs produce different
// derived root keys and chain keys, ensuring that each ratchet step generates unique
// cryptographic material for forward secrecy.
func TestRootKeyDerivationUniqueness(t *testing.T) {
	var rk ChainKey

	copy(rk[:], []byte("rootkey0123456789012345678901234"))

	dhOut1 := []byte("dhoutput1")
	dhOut2 := []byte("dhoutput2")

	nextRk1, nextCk1 := DeriveRK(rk, dhOut1)
	nextRk2, nextCk2 := DeriveRK(rk, dhOut2)

	if nextRk1 == nextRk2 {
		t.Error("Different DH outputs should produce different Root Keys")
	}
	if nextCk1 == nextCk2 {
		t.Error("Different DH outputs should produce different Chain Keys")
	}
}

// TestChainKeyDerivationChaining verifies that multiple consecutive chain key derivations
// produce unique chain keys and message keys at each step, ensuring proper key evolution
// throughout the message chain.
func TestChainKeyDerivationChaining(t *testing.T) {
	var ck ChainKey

	copy(ck[:], []byte("chainkey012345678901234567890123"))

	const steps = 10

	prevCk := ck

	for i := range steps {
		nextCk, mk := DeriveCK(prevCk)

		if nextCk == prevCk {
			t.Errorf("Step %d: Next Chain Key should differ from previous", i)
		}

		zeroMk := MessageKey{}

		if mk == zeroMk {
			t.Errorf("Step %d: Message Key should not be zero", i)
		}

		prevCk = nextCk
	}
}

// TestChainKeyDerivationDeterminism verifies that deriving from the same chain key
// multiple times produces identical results, ensuring deterministic behavior required
// for protocol correctness and message key synchronization.
func TestChainKeyDerivationDeterminism(t *testing.T) {
	var ck ChainKey
	copy(ck[:], []byte("chainkey012345678901234567890123"))

	nextCk1, mk1 := DeriveCK(ck)
	nextCk2, mk2 := DeriveCK(ck)

	if nextCk1 != nextCk2 {
		t.Error("DeriveCK should be deterministic for the same input Chain Key")
	}
	if mk1 != mk2 {
		t.Error("DeriveCK should produce deterministic Message Key for the same input Chain Key")
	}
}

// TestRootKeyAndChainKeyDerivationDeterminism verifies that DeriveRK is deterministic,
// producing the same root key and chain key when called multiple times with the same
// inputs, ensuring consistent state across protocol participants.
func TestRootKeyAndChainKeyDerivationDeterminism(t *testing.T) {
	var rk ChainKey
	copy(rk[:], []byte("rootkey0123456789012345678901234"))

	dhOut := []byte("dhoutput")

	nextRk1, nextCk1 := DeriveRK(rk, dhOut)
	nextRk2, nextCk2 := DeriveRK(rk, dhOut)

	if nextRk1 != nextRk2 || nextCk1 != nextCk2 {
		t.Error("DeriveRK should be deterministic for same inputs")
	}
}
