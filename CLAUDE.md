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

**Note**: SERVER_ADDRESS can be a comma-separated list of servers for failover support. The client will try each server in order until one successfully provides a certificate.

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
4. Server generates certificate signed by its CA
5. Server connects back to client, sends the certificate as unencrypted payload
6. Client saves the certificate and private key to files
7. The certificate and private key can be used with web servers or other TLS services