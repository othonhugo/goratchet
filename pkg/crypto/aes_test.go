package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	var mk MessageKey

	copy(mk[:], []byte("01234567890123456789012345678901"))

	plaintext := []byte("Hello World")
	ad := []byte("Associated Data")

	ciphertext, err := Encrypt(mk, plaintext, ad)

	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(mk, ciphertext, ad)

	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Expected %s, got %s", plaintext, decrypted)
	}
}

func TestDecryptErrors(t *testing.T) {
	var mk MessageKey

	copy(mk[:], []byte("01234567890123456789012345678901"))

	plaintext := []byte("Hello World")
	ad := []byte("Associated Data")

	ciphertext, _ := Encrypt(mk, plaintext, ad)

	if _, err := Decrypt(mk, ciphertext[:10], ad); err != ErrCiphertextTooShort {
		t.Errorf("Expected ErrCiphertextTooShort, got %v", err)
	}

	corrupted := make([]byte, len(ciphertext))

	copy(corrupted, ciphertext)

	corrupted[len(corrupted)-1] ^= 0xFF

	if _, err := Decrypt(mk, corrupted, ad); err == nil {
		t.Error("Expected error for corrupted ciphertext, got nil")
	}

	if _, err := Decrypt(mk, ciphertext, []byte("Wrong AD")); err == nil {
		t.Error("Expected error for wrong AD, got nil")
	}
}

func TestEncryptDecryptVariousLengths(t *testing.T) {
	var mk MessageKey

	copy(mk[:], []byte("01234567890123456789012345678901"))

	lengths := []int{0, 1, 16, 31, 32, 64, 128, 1024, 4096}

	for _, n := range lengths {
		plaintext := bytes.Repeat([]byte("A"), n)
		ad := []byte("AD")

		ciphertext, err := Encrypt(mk, plaintext, ad)

		if err != nil {
			t.Fatalf("Encrypt failed for length %d: %v", n, err)
		}

		decrypted, err := Decrypt(mk, ciphertext, ad)

		if err != nil {
			t.Fatalf("Decrypt failed for length %d: %v", n, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Length %d: decrypted does not match plaintext", n)
		}
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	var mk1, mk2 MessageKey

	copy(mk1[:], []byte("01234567890123456789012345678901"))
	copy(mk2[:], []byte("11111111111111111111111111111111"))

	plaintext := []byte("Hello World")
	ad := []byte("AD")

	ciphertext, err := Encrypt(mk1, plaintext, ad)

	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if _, err := Decrypt(mk2, ciphertext, ad); err == nil {
		t.Error("Expected error when decrypting with wrong key, got nil")
	}
}

func TestEncryptDecryptNilAD(t *testing.T) {
	var mk MessageKey

	copy(mk[:], []byte("01234567890123456789012345678901"))

	plaintext := []byte("Hello World")

	ciphertext, err := Encrypt(mk, plaintext, nil)

	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(mk, ciphertext, nil)

	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Expected %s, got %s", plaintext, decrypted)
	}
}

func TestDecryptRandomData(t *testing.T) {
	var mk MessageKey

	copy(mk[:], []byte("01234567890123456789012345678901"))

	random := make([]byte, 64)

	for i := range random {
		random[i] = byte(i * 3 % 256)
	}

	if _, err := Decrypt(mk, random, []byte("AD")); err == nil {
		t.Error("Expected error for random ciphertext, got nil")
	}
}

func TestEncryptNonDeterministic(t *testing.T) {
	var mk MessageKey

	copy(mk[:], []byte("01234567890123456789012345678901"))

	plaintext := []byte("Hello World")
	ad := []byte("AD")

	ct1, _ := Encrypt(mk, plaintext, ad)
	ct2, _ := Encrypt(mk, plaintext, ad)

	if bytes.Equal(ct1, ct2) {
		t.Error("Expected ciphertexts to differ on multiple encryptions")
	}
}
