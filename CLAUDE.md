# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LessEncrypt is a certificate encryption and decryption system with a client-server architecture using public key handshaking. The system consists of:

- `client.py`: Handles key generation, server connection, and payload decryption
- `server.py`: Manages client connections, key processing, and payload encryption

## Development Commands

### Running the Server
```bash
./server.py PATH_TO_PAYLOAD_FILE [--listen IP] [--port PORT] [--timeout SECONDS]
```

### Running the Client
```bash
./client.py SERVER_ADDRESS OUTPUT_FILE [--timeout SECONDS] [--port PORT]
```

### Type Checking
```bash
mypy --strict client.py server.py
```

### Code Formatting
```bash
black client.py server.py
```

## Protocol Flow

1. Client generates RSA key pair
2. Client connects to server and sends public key
3. Server acknowledges with "ok"
4. Server generates AES session key, encrypts with client's public key
5. Server connects back to client, sends encrypted session key and payload
6. Client decrypts session key with private key
7. Client decrypts payload with session key
8. Client saves decrypted payload to file