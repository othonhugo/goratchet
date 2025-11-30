package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveHKDF(t *testing.T) {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")
	length := 32

	out, err := DeriveHKDF(secret, salt, info, length)

	if err != nil {
		t.Fatalf("DeriveHKDF failed: %v", err)
	}

	if len(out) != length {
		t.Errorf("Expected length %d, got %d", length, len(out))
	}

	// Test with nil salt
	out2, err := DeriveHKDF(secret, nil, info, length)

	if err != nil {
		t.Fatalf("DeriveHKDF failed: %v", err)
	}
	if len(out2) != length {
		t.Errorf("Expected length %d, got %d", length, len(out2))
	}
}

func TestDeriveRK(t *testing.T) {
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

func TestDeriveCK(t *testing.T) {
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

func TestDeriveHKDFVariousLengths(t *testing.T) {
	secret := []byte("secret")
	salt := []byte("salt")
	info := []byte("info")

	lengths := []int{0, 1, 16, 32, 64, 128}

	for _, l := range lengths {
		out, err := DeriveHKDF(secret, salt, info, l)
		if err != nil {
			t.Fatalf("DeriveHKDF failed for length %d: %v", l, err)
		}
		if len(out) != l {
			t.Errorf("Expected length %d, got %d", l, len(out))
		}
	}
}

func TestDeriveHKDFNilSalt(t *testing.T) {
	secret := []byte("secret")
	info := []byte("info")
	length := 32

	out1, err := DeriveHKDF(secret, nil, info, length)
	if err != nil {
		t.Fatalf("DeriveHKDF failed with nil salt: %v", err)
	}

	out2, err := DeriveHKDF(secret, []byte{}, info, length)
	if err != nil {
		t.Fatalf("DeriveHKDF failed with empty salt: %v", err)
	}

	if !bytes.Equal(out1, out2) {
		t.Errorf("Expected nil and empty salt to produce same output")
	}
}

func TestDeriveRKUniqueness(t *testing.T) {
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

func TestDeriveCKMultipleSteps(t *testing.T) {
	var ck ChainKey
	copy(ck[:], []byte("chainkey012345678901234567890123"))

	const steps = 10
	prevCk := ck

	for i := 0; i < steps; i++ {
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

func TestDeriveCKDeterminism(t *testing.T) {
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

func TestDeriveRKAndCKIndependence(t *testing.T) {
	var rk ChainKey
	copy(rk[:], []byte("rootkey0123456789012345678901234"))

	dhOut := []byte("dhoutput")

	nextRk1, nextCk1 := DeriveRK(rk, dhOut)
	nextRk2, nextCk2 := DeriveRK(rk, dhOut)

	if nextRk1 != nextRk2 || nextCk1 != nextCk2 {
		t.Error("DeriveRK should be deterministic for same inputs")
	}
}
