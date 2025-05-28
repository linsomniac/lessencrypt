# LessEncrypt Protocol Documentation

## Overview

LessEncrypt is a certificate encryption and decryption system with a client-server architecture using public key handshaking. The protocol supports optional shared secret authentication for enhanced security.

## Protocol Flow

### Basic Flow (Without Authentication)

1. **Client connects** to server on configured port (default: 334), from configured port (default: 334).
2. **Server sends** initial protocol message: `lessencrypt\n`
3. **Client sends** key request with public key
4. **Server responds** with acknowledgment: `ok\n`
5. **Server generates** certificate signed by its CA
6. **Server connects back** to client on port they connected to server on
7. **Server sends** certificate payload (client cert + CA cert)
8. **Client saves** certificate and private key to files

### Authenticated Flow (With Shared Secret)

1. **Client connects** to server on configured port (default: 334)
2. **Server sends** protocol message with challenge: `lessencrypt challenge=<32-char-base64>\n`
3. **Client calculates** challenge response: `SHA256(shared_secret + challenge)`
4. **Client sends** key request with challenge response
5. **Server verifies** challenge response
6. **Server responds** with acknowledgment: `ok\n` (or error if verification fails)
7. **Server generates** certificate signed by its CA
8. **Server connects back** to client on port they connected to server on
9. **Server sends** certificate payload (client cert + CA cert)
10. **Client saves** certificate and private key to files

## Message Formats

### Protocol Messages

All protocol messages are UTF-8 encoded text terminated with `\n`.

#### Server Initial Message

**Without authentication:**

```
lessencrypt\n
```

**With authentication:**

```
lessencrypt challenge=<CHALLENGE>\n
```

Where `<CHALLENGE>` is 32 random base64 characters (24 bytes encoded as base64).

#### Client Key Request

**Without authentication:**

```
keyreq v=1 pubkey=<PUBLIC_KEY>\n
```

**With authentication:**

```
keyreq v=1 challenge_response=<RESPONSE> pubkey=<PUBLIC_KEY>\n
```

**Parameters:**

- `v`: Protocol version (currently "1")
- `challenge_response`: SHA256 hex digest of `shared_secret + challenge`
- `pubkey`: Client's RSA public key in PEM format, base64 encoded

#### Server Response Messages

**Success:**

```
ok\n
```

**Error:**

```
error msg=<ERROR_MESSAGE>\n
```

Common error messages:

- `Failed to resolve hostname`
- `No mapping found for <hostname>`
- `Invalid key request format`
- `Challenge response required`
- `Invalid challenge response`
- `Missing public key in request`
- `Invalid public key: <details>`

#### Certificate Delivery Message

**Header:**

```
cert v=2 payloadlength=<LENGTH>\n
```

**Payload:**
The payload immediately follows the header and contains:

1. Client certificate (PEM format)
2. CA certificate (PEM format)

Both certificates are concatenated without additional separators.

## Authentication

### Shared Secret Configuration

**Server configuration** (`lessencrypt.conf`):

```ini
[server]
shared_secret = your_secret_here
```

**Client usage:**

```bash
./lessencryptcli server.example.com output.pem --shared-secret "your_secret_here"
```

### Challenge-Response Mechanism

1. **Challenge Generation**: Server generates 24 random bytes, encodes as base64 (32 characters)
2. **Response Calculation**: Client computes `SHA256(shared_secret + challenge)` as hex digest
3. **Verification**: Server performs same calculation and compares results

**Example:**

```
Shared secret: "mysecret"
Challenge: "abc123def456ghi789jkl012mno345pq"
Concatenated: "mysecretabc123def456ghi789jkl012mno345pq"
Response: SHA256 hex digest of the concatenated string
```

## Protocol Versions

### Version 1 (Current)

- Uses unencrypted certificate delivery
- Certificates are public information, encryption unnecessary
- Payload contains client cert + CA cert in PEM format
- Supports optional shared secret authentication

## Security Considerations

### Shared Secret Security

- Shared secrets should be sufficiently long and random
- Challenge-response prevents replay and reduces third-party DoS attacks
- SHA256 provides cryptographic security for response verification

### Certificate Security

- Private keys are generated client-side and never transmitted
- Only public keys are sent to the server
- Certificates are public information and transmitted unencrypted
- Private key files are written with restricted permissions (600)

### Network Security

- Challenge-response provides authentication but not encryption
