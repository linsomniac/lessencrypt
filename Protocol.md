# LessEncrypt Protocol Documentation

## Overview

LessEncrypt is a certificate encryption and decryption system with a client-server architecture using public key handshaking. The protocol supports optional shared secret authentication for enhanced security.

## Protocol Flow

### Current Flow (Protocol v1 - Enhanced Security)

1. **Client connects** to server on configured port (default: 334), from configured port (default: 334).
2. **Server sends** protocol message with challenge: `lessencrypt challenge=<32-char-base64>\n`
3. **Client signs** the challenge (optionally with shared secret):
   - If shared secret configured: signs `SHA256(shared_secret + challenge)` with private key
   - If no shared secret: signs `SHA256(challenge)` with private key
4. **Client sends** challenge signature and public key as:`"keyreq v=1 challenge_signature=<base64 data> pubkey=<base64 data>\n`
5. **Server verifies** challenge signature using client's public key
6. **Server responds** with acknowledgment: `ok\n` (or `error=XXX\n` if verification fails)
7. **Server generates** certificate signed by its CA
8. **Server connects back** to client on port they connected to server on
9. **Server sends** encrypted certificate payload using hybrid encryption (RSA + AES-GCM)
   `cert v=1 payloadlength=6982\n<payload>`
10. **Client decrypts** certificate payload using private key
11. **Client saves** certificate and private key to files

## Message Formats

### Protocol Messages

All protocol messages are UTF-8 encoded text terminated with `\n`.

#### Server Initial Message

**Current (v1 - always includes challenge):**

```
lessencrypt challenge=<CHALLENGE>\n
```

Where `<CHALLENGE>` is 32 random base64 characters (24 bytes encoded as base64).

#### Client Key Request

**Current (v1 - always includes challenge signature):**

```
keyreq v=1 challenge_signature=<SIGNATURE> pubkey=<PUBLIC_KEY>\n
```

**Parameters:**

- `v`: Protocol version (currently "1")
- `challenge_signature`: RSA signature of the challenge message, base64 encoded
  - Message signed: `shared_secret + challenge` (if shared secret configured) or `challenge` (if no shared secret)
  - Signature algorithm: RSA-PSS with SHA-256, MGF1-SHA256, max salt length
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
- `Challenge signature required`
- `Invalid challenge signature: <details>`
- `Missing public key in request`
- `Invalid public key: <details>`

#### Certificate Delivery Message

**Header (v1 - encrypted):**

```
cert v=1 payloadlength=<LENGTH>\n
```

**Payload (v1 - hybrid encrypted):**
The payload immediately follows the header and contains encrypted certificate data in the following format:

1. **Encrypted AES key length** (4 bytes, big-endian)
2. **Encrypted AES key** (RSA-OAEP encrypted with client's public key)
3. **IV length** (4 bytes, big-endian)
4. **AES-GCM IV** (16 bytes)
5. **Encrypted certificate data** (AES-GCM encrypted)

The encrypted certificate data contains:

1. Client certificate (PEM format)
2. CA certificate (PEM format)

Both certificates are concatenated without additional separators before encryption.

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

```ini
[client]
shared_secret = your_secret_here
```

### Challenge-Signature Mechanism (v1)

1. **Challenge Generation**: Server generates 24 random bytes, encodes as base64 (32 characters)
2. **Message Preparation**: Client prepares message to sign:
   - With shared secret: `SHA256(shared_secret + challenge)`
   - Without shared secret: `SHA256(challenge)`
3. **Signature Creation**: Client signs the message using RSA-PSS with SHA-256
4. **Verification**: Server verifies signature using client's public key

**Example:**

```
Shared secret: "mysecret"
Challenge: "abc123def456ghi789jkl012mno345pq"
Message to sign: "SHA256(mysecretabc123def456ghi789jkl012mno345pq)"
Signature: RSA-PSS signature of the message, base64 encoded
```

## Protocol Versions

### Version 1 (Current)

- Uses hybrid encryption for certificate delivery (RSA-OAEP + AES-GCM)
- Mandatory challenge-response authentication using digital signatures
- Enhanced security against port takeover and man-in-the-middle attacks
- Payload contains encrypted client cert + CA cert in PEM format
- Supports optional shared secret for additional authentication

## Security Considerations

### Enhanced Authentication Security (v1)

- Digital signatures prevent impersonation and replay attacks
- Challenge uniqueness ensures freshness of authentication
- RSA-PSS with SHA-256 provides strong cryptographic security and guarantee of delivery to
  requester
- Optional shared secret adds an additional guarantee of authorization of client and
  preventing resource consumption as DoS

### Certificate Security

- Private keys are generated client-side and never transmitted
- Only public keys are sent to the server
- Certificates are encrypted during transmission using hybrid encryption
- Private key files are written with restricted permissions (600)
- Certificate encryption prevents unauthorized interception, though data is not high security

### Network Security

- Hybrid encryption (RSA-OAEP + AES-GCM) provides confidentiality
- Protection against port takeover attacks through: low port number and shared secret
- Forward secrecy through random AES keys for each certificate delivery

### Cryptographic Algorithms

- **Key Exchange**: RSA-OAEP with SHA-256
- **Symmetric Encryption**: AES-256-GCM
- **Digital Signatures**: RSA-PSS with SHA-256, MGF1-SHA256, max salt length
- **Random Number Generation**: Cryptographically secure random generators
