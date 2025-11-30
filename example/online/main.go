// nolint:all // Example code: focus on clarity over style
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"

	"github.com/othonhugo/goratchet"
	"github.com/othonhugo/goratchet/pkg/doubleratchet"
)

const (
	defaultPort = "8080"
	defaultHost = "localhost"
)

// message represents a network message with encrypted content
type message struct {
	Header     doubleratchet.Header `json:"header"`
	Ciphertext []byte               `json:"ciphertext"`
}

func main() {
	mode := flag.String("mode", "server", "Mode: 'server' or 'client'")
	host := flag.String("host", defaultHost, "Host address")
	port := flag.String("port", defaultPort, "Port number")

	flag.Parse()

	switch *mode {
	case "server":
		runServer(*host, *port)
	case "client":
		runClient(*host, *port)
	default:
		log.Fatalf("Invalid mode: %s. Use 'server' or 'client'", *mode)
	}
}

func runServer(host, port string) {
	addr := net.JoinHostPort(host, port)

	listener, err := net.Listen("tcp", addr)

	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	defer listener.Close()

	log.Printf("Server listening on %s", addr)

	for {
		conn, err := listener.Accept()

		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		log.Printf("Client connected from %s", conn.RemoteAddr())

		go handleConnection(conn, true)
	}
}

func runClient(host, port string) {
	addr := net.JoinHostPort(host, port)
	conn, err := net.Dial("tcp", addr)

	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}

	defer conn.Close()

	log.Printf("Connected to server at %s", addr)

	handleConnection(conn, false)
}

func handleConnection(conn net.Conn, isServer bool) {
	defer conn.Close()

	// Step 1: Generate local key pair
	localPri, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Step 2: Exchange public keys
	remotePub, err := exchangePublicKeys(conn, localPri.PublicKey(), isServer)

	if err != nil {
		log.Fatalf("Key exchange failed: %v", err)
	}

	log.Printf("Key exchange completed")

	// Step 3: Initialize Double Ratchet session
	session, err := goratchet.New(localPri.Bytes(), remotePub)

	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	log.Printf("Double Ratchet session initialized")

	// Step 4: Start message exchange
	if isServer {
		serverChat(conn, session)
	} else {
		clientChat(conn, session)
	}
}

// exchangePublicKeys performs the initial public key exchange
func exchangePublicKeys(conn net.Conn, localPub *ecdh.PublicKey, isServer bool) ([]byte, error) {
	localPubBytes := localPub.Bytes()

	if isServer {
		// Server: receive first, then send
		remotePubBytes, err := receiveBytes(conn)

		if err != nil {
			return nil, fmt.Errorf("failed to receive client public key: %w", err)
		}

		if err := sendBytes(conn, localPubBytes); err != nil {
			return nil, fmt.Errorf("failed to send server public key: %w", err)
		}

		return remotePubBytes, nil
	}

	// Client: send first, then receive
	if err := sendBytes(conn, localPubBytes); err != nil {
		return nil, fmt.Errorf("failed to send client public key: %w", err)
	}

	remotePubBytes, err := receiveBytes(conn)

	if err != nil {
		return nil, fmt.Errorf("failed to receive server public key: %w", err)
	}

	return remotePubBytes, nil
}

func serverChat(conn net.Conn, session goratchet.DoubleRatchet) {
	// Server receives messages and responds
	for {
		// Receive encrypted message
		ciphered, err := receiveMessage(conn)

		if err != nil {
			if err == io.EOF {
				log.Println("Client disconnected")
				return
			}
			log.Printf("Failed to receive message: %v", err)
			return
		}

		// Decrypt message
		unciphered, err := session.Receive(ciphered, nil)

		if err != nil {
			log.Printf("Failed to decrypt message: %v", err)
			return
		}

		log.Printf("Client: %s", string(unciphered.Plaintext))

		// Send response
		response := fmt.Sprintf("Echo: %s", string(unciphered.Plaintext))
		cipheredResponse, err := session.Send([]byte(response), nil)

		if err != nil {
			log.Printf("Failed to encrypt response: %v", err)
			return
		}

		if err := sendMessage(conn, cipheredResponse); err != nil {
			log.Printf("Failed to send response: %v", err)
			return
		}
	}
}

func clientChat(conn net.Conn, session goratchet.DoubleRatchet) {
	// Client sends messages and receives responses
	messages := []string{
		"Hello, Server!",
		"How are you?",
		"This is a secure message.",
		"Testing Double Ratchet protocol.",
		"Goodbye!",
	}

	for _, msg := range messages {
		// Encrypt and send message
		ciphered, err := session.Send([]byte(msg), nil)

		if err != nil {
			log.Printf("Failed to encrypt message: %v", err)
			return
		}

		log.Printf("Sending: %s", msg)

		if err := sendMessage(conn, ciphered); err != nil {
			log.Printf("Failed to send message: %v", err)
			return
		}

		// Receive and decrypt response
		cipheredResponse, err := receiveMessage(conn)

		if err != nil {
			log.Printf("Failed to receive response: %v", err)
			return
		}

		unciphered, err := session.Receive(cipheredResponse, nil)

		if err != nil {
			log.Printf("Failed to decrypt response: %v", err)
			return
		}

		log.Printf("Server: %s", string(unciphered.Plaintext))
	}

	log.Println("All messages sent successfully")
}

// sendMessage sends an encrypted message over the connection
func sendMessage(conn net.Conn, msg goratchet.CipheredMessage) error {
	data, err := json.Marshal(message{
		Header:     msg.Header,
		Ciphertext: msg.Ciphertext,
	})

	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return sendBytes(conn, data)
}

// receiveMessage receives an encrypted message from the connection
func receiveMessage(conn net.Conn) (goratchet.CipheredMessage, error) {
	data, err := receiveBytes(conn)

	if err != nil {
		return goratchet.CipheredMessage{}, err
	}

	var msg message

	if err := json.Unmarshal(data, &msg); err != nil {
		return goratchet.CipheredMessage{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return goratchet.CipheredMessage{
		Header:     msg.Header,
		Ciphertext: msg.Ciphertext,
	}, nil
}

// sendBytes sends a length-prefixed byte slice
func sendBytes(conn net.Conn, data []byte) error {
	if len(data) > math.MaxUint32 {
		return fmt.Errorf("data too large")
	}

	// Send length (4 bytes)
	length := uint32(len(data))

	lengthBytes := []byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	}

	if _, err := conn.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to write length: %w", err)
	}

	// Send data
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return nil
}

// receiveBytes receives a length-prefixed byte slice
func receiveBytes(conn net.Conn) ([]byte, error) {
	// Read length (4 bytes)
	lengthBytes := make([]byte, 4)

	if _, err := io.ReadFull(conn, lengthBytes); err != nil {
		return nil, err
	}

	length := uint32(lengthBytes[0])<<24 |
		uint32(lengthBytes[1])<<16 |
		uint32(lengthBytes[2])<<8 |
		uint32(lengthBytes[3])

	// Sanity check
	if length > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return data, nil
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime | log.Lmicroseconds)
}
