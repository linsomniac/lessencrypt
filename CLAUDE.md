# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LessEncrypt is a certificate encryption and decryption system with a client-server architecture using public key handshaking. The system consists of:

- `lessencryptcli`: Handles key generation, server connection, and certificate decryption
- `lessencryptserver`: Manages client connections, key processing, and certificate signing

## Development Commands

### Running the Server
```bash
./lessencryptserver [--config CONFIG_PATH] [--listen IP] [--port PORT] [--timeout SECONDS] [--verbose] [--debug]
```

### Running the Client
```bash
./lessencryptcli SERVER_ADDRESS OUTPUT_FILE [--port PORT] [--timeout SECONDS] [--key-size BITS] [--passphrase PASSPHRASE]
```

### Type Checking
```bash
mypy --strict lessencryptcli lessencryptserver
```

### Code Formatting
```bash
black lessencryptcli lessencryptserver
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