# Offline Example - Basic GoRatchet Usage

This example demonstrates the simplest possible usage of GoRatchet for local, in-memory encrypted communication between two parties (Alice and Bob).

## Overview

This is a minimal example showing:
- Key pair generation for both parties
- Session initialization
- Encrypting a message
- Decrypting a message

**No network communication is involved** - both parties exist in the same process, making this ideal for:
- Learning the GoRatchet API
- Testing and development
- Understanding the Double Ratchet protocol
- Integration testing

## Usage

Run the example:

```bash
go run example/offline/main.go
```

## Example Output

```
Ciphertext: 8A4875ABC90670A21BB817C4B76931CA46C6EB3FC79FD3FBE13A72C0B7490E290F6656ECA721D0181F
Plaintext: hello, there!
```