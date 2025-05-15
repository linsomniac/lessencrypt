# LessEncrypt

A simple certificate encryption and decryption system with public key handshaking.

## Requirements

The programs use the uv script mechanism with the following requirements:
- Python 3.8+
- cryptography
- pydantic
- black
- mypy

## Usage

### Server

The server encrypts a payload file and sends it to clients upon request.

```bash
./server.py PATH_TO_PAYLOAD_FILE [--listen IP] [--port PORT] [--timeout SECONDS]
```

Options:
- `PATH_TO_PAYLOAD_FILE`: File to encrypt and send
- `--listen`: Address to listen on (default: 0.0.0.0)
- `--port`: Port to listen on (default: 334)
- `--timeout`: Connection timeout in seconds (default: 60)

### Client

The client requests and decrypts a certificate from the server.

```bash
./client.py SERVER_ADDRESS OUTPUT_FILE [--timeout SECONDS] [--port PORT]
```

Options:
- `SERVER_ADDRESS`: Address of the server
- `OUTPUT_FILE`: Path to save the decrypted payload
- `--timeout`: Timeout for server connection in seconds (default: 60)
- `--port`: Port to use for connections (default: 334)

## Protocol Flow

1. Client generates RSA key pair
2. Client connects to server and sends public key
3. Server acknowledges with "ok"
4. Server generates AES session key, encrypts with client's public key
5. Server connects back to client, sends encrypted session key and payload
6. Client decrypts session key with private key
7. Client decrypts payload with session key
8. Client saves decrypted payload to file