# Double Ratchet

A straightforward and easy-to-understand Go implementation of the [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/), designed for clarity and ease of integration into Go projects requiring robust end-to-end encryption.

> [!CAUTION]
> This implementation is not intended for production use. It is provided for educational purposes only. Use at your own risk.

## Features

- **Full Double Ratchet Implementation**: Adheres strictly to the Signal Protocol's Double Ratchet Algorithm specification, providing robust forward secrecy and deniability for end-to-end encrypted messaging sessions.
- **Standardized Cryptography**: Utilizes Go's built-in, cryptographically secure packages, specifically `crypto/ecdh` for elliptic curve Diffie-Hellman key exchange (using P256 curves) and HKDF (HMAC-based Key Derivation Function) for secure key derivation, ensuring reliance on well-audited primitives.
- **Resilient Message Handling**: Incorporates mechanisms to gracefully handle out-of-order message delivery and recover skipped message keys, enhancing the protocol's robustness in unreliable network environments.
- **Developer-Friendly API**: Offers a minimalist and intuitive API, centered around `Send` and `Receive` methods, designed for ease of integration into existing Go applications, abstracting away complex cryptographic operations.

## Installation

```bash
go get github.com/othonhugo/doubleratchet
```

## Usage

The following example demonstrates how to establish a session between two parties (Alice and Bob) and exchange messages.

> [!NOTE]
> For simplicity, error handling has been omitted in this example.

```go
// 1. Generate Identity Keys for Alice and Bob

alicePri, _ := ecdh.P256().GenerateKey(rand.Reader)
bobPri, _ := ecdh.P256().GenerateKey(rand.Reader)

// 2. Initialize Sessions

// Alice initializes with her private key and Bob's public key
alice, _ := doubleratchet.New(alicePri.Bytes(), bobPri.PublicKey().Bytes())

// Bob initializes with his private key and Alice's public key
bob, _ := doubleratchet.New(bobPri.Bytes(), alicePri.PublicKey().Bytes())

// 3. Alice sends a message to Bob

message := []byte("Hello, Bob!")
ciphered, _ := alice.Send(message, nil) // nil is for associated data (AD)

fmt.Printf("Alice sent ciphertext: %x\n", ciphered.Ciphertext)

// 4. Bob receives the message

unciphered, _ := bob.Receive(ciphered, nil)

fmt.Printf("Bob received plaintext: %s\n", unciphered.Plaintext)
```

## How it works

The Double Ratchet algorithm provides:
- **Forward Secrecy**: Old keys cannot be compromised if the current keys are leaked.
- **Post-Compromise Security**: Future keys will be secure even if the current keys are leaked (after a new DH ratchet step).

It achieves this by combining a **Diffie-Hellman Ratchet** (updates root keys based on new DH exchanges) and a **Symmetric-Key Ratchet** (derives per-message keys).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
