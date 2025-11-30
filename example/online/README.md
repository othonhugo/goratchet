# Online Example - Network Communication with GoRatchet

This example demonstrates how to use GoRatchet for secure end-to-end encrypted communication over a network using `net.Conn`.

## Features

- **TCP-based communication**: Client-server architecture using Go's `net` package
- **Public key exchange**: Automatic ECDH public key exchange on connection
- **Encrypted messaging**: All messages are encrypted using the Double Ratchet protocol
- **Bidirectional communication**: Both client and server can send and receive messages
- **Length-prefixed framing**: Proper message framing for reliable TCP communication

## Usage

### Running the Server

In one terminal, start the server:

```bash
go run example/online/main.go -mode server
```

Or with custom host and port:

```bash
go run example/online/main.go -mode server -host localhost -port 9000
```

### Running the Client

In another terminal, start the client:

```bash
go run example/online/main.go -mode client
```

Or with custom host and port:

```bash
go run example/online/main.go -mode client -host localhost -port 9000
```

## Example Output

### Server Output:

```
23:33:46.410965 Server listening on localhost:8080
23:33:54.732018 Client connected from 127.0.0.1:49960
23:33:54.732203 Key exchange completed
23:33:54.732329 Double Ratchet session initialized
23:33:54.732523 Client: Hello, Server!
23:33:54.732761 Client: How are you?
23:33:54.733000 Client: This is a secure message.
23:33:54.733400 Client: Testing Double Ratchet protocol.
23:33:54.733678 Client: Goodbye!
23:33:54.733888 Client disconnected
```

### Client Output:

```
23:33:54.731977 Connected to server at localhost:8080
23:33:54.732227 Key exchange completed
23:33:54.732317 Double Ratchet session initialized
23:33:54.732351 Sending: Hello, Server!
23:33:54.732648 Server: Echo: Hello, Server!
23:33:54.732675 Sending: How are you?
23:33:54.732869 Server: Echo: How are you?
23:33:54.732895 Sending: This is a secure message.
23:33:54.733117 Server: Echo: This is a secure message.
23:33:54.733292 Sending: Testing Double Ratchet protocol.
23:33:54.733523 Server: Echo: Testing Double Ratchet protocol.
23:33:54.733559 Sending: Goodbye!
23:33:54.733800 Server: Echo: Goodbye!
23:33:54.733822 All messages sent successfully
```