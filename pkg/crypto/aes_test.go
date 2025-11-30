package crypto

import (
	"bytes"
	"testing"
)

// TestAESGCMEncryptDecryptRoundTrip verifies that the AES-GCM encryption and decryption
// functions work correctly together, ensuring that plaintext can be encrypted and then
// decrypted back to the original value with associated data authentication.
func TestAESGCMEncryptDecryptRoundTrip(t *testing.T) {
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

// TestAESGCMDecryptionErrorHandling verifies that the Decrypt function properly handles
// various error conditions including short ciphertext, corrupted data, and incorrect
// associated data, ensuring robust error detection.
func TestAESGCMDecryptionErrorHandling(t *testing.T) {
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

// TestAESGCMEncryptDecryptVariousMessageSizes verifies that encryption and decryption
// work correctly for messages of various sizes from empty to large (4KB), ensuring
// the implementation handles different payload sizes correctly.
func TestAESGCMEncryptDecryptVariousMessageSizes(t *testing.T) {
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

// TestAESGCMDecryptionWithIncorrectKey verifies that attempting to decrypt a message
// with a different key than the one used for encryption fails, ensuring key-based
// authentication and preventing unauthorized decryption.
func TestAESGCMDecryptionWithIncorrectKey(t *testing.T) {
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

// TestAESGCMEncryptDecryptWithoutAssociatedData verifies that encryption and decryption
// work correctly when no associated data is provided (nil AD), ensuring the implementation
// handles optional associated data properly.
func TestAESGCMEncryptDecryptWithoutAssociatedData(t *testing.T) {
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

// TestAESGCMDecryptionOfRandomDataFails verifies that attempting to decrypt random
// or malformed data fails gracefully, ensuring the implementation doesn't accept
// invalid ciphertext and maintains security.
func TestAESGCMDecryptionOfRandomDataFails(t *testing.T) {
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

// TestAESGCMEncryptionNonDeterministic verifies that encrypting the same plaintext
// multiple times produces different ciphertexts due to random nonce generation,
// ensuring semantic security and preventing pattern analysis.
func TestAESGCMEncryptionNonDeterministic(t *testing.T) {
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
