#!/usr/bin/env python3
# requires: cryptography pydantic black mypy

import argparse
import base64
import socket
import sys
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a new RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encode_public_key(public_key: rsa.RSAPublicKey) -> str:
    """Encode a public key as a base64 string."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode("utf-8")


def decrypt_session_key(
    session_key_b64: str, private_key: rsa.RSAPrivateKey
) -> bytes:
    """Decrypt the session key using our private key."""
    encrypted_session_key = base64.b64decode(session_key_b64)
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return session_key


def decrypt_payload(payload: bytes, session_key: bytes) -> bytes:
    """Decrypt the payload using the session key."""
    # Assuming first 16 bytes are the IV
    iv = payload[:16]
    ciphertext = payload[16:]
    
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]


def main() -> None:
    parser = argparse.ArgumentParser(description="Certificate decryption client")
    parser.add_argument("server", help="Server to connect to")
    parser.add_argument("output", help="Output file for the decrypted certificate")
    parser.add_argument(
        "--timeout", type=int, default=60, help="Timeout for server connection in seconds"
    )
    parser.add_argument(
        "--port", type=int, default=334, help="Port to use for connections"
    )
    args = parser.parse_args()

    # Generate keypair
    private_key, public_key = generate_keypair()
    pubkey_b64 = encode_public_key(public_key)

    # Start listening on our port
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", args.port))
    listener.listen(1)
    listener.settimeout(args.timeout)

    # Connect to server
    print(f"Connecting to server {args.server}:{args.port}")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((args.server, args.port))
    
    # Send key request
    key_req = f"keyreq v=1 pubkey={pubkey_b64}\n"
    server_sock.sendall(key_req.encode())
    
    # Wait for "ok" response
    response = server_sock.recv(1024).decode()
    if response.strip() != "ok":
        print(f"Unexpected response from server: {response}")
        sys.exit(1)
    
    print("Server acknowledged our key request")
    server_sock.close()
    
    # Now wait for incoming connection with the encrypted certificate
    print(f"Waiting for incoming connection on port {args.port}")
    try:
        client_sock, addr = listener.accept()
        print(f"Received connection from {addr[0]}:{addr[1]}")
        
        # Read the certificate line
        cert_line = client_sock.recv(4096).decode()
        
        # Parse the certificate line
        if not cert_line.startswith("cert v=1 "):
            print(f"Invalid certificate line: {cert_line}")
            sys.exit(1)
        
        parts = cert_line.strip().split()
        session_key_b64 = None
        payload_length = None
        
        for part in parts:
            if part.startswith("sessionkey="):
                session_key_b64 = part[len("sessionkey="):]
            elif part.startswith("payloadlength="):
                payload_length = int(part[len("payloadlength="):])
        
        if session_key_b64 is None or payload_length is None:
            print(f"Missing required fields in certificate line: {cert_line}")
            sys.exit(1)
        
        # Read the payload
        payload = b""
        bytes_received = 0
        
        while bytes_received < payload_length:
            chunk = client_sock.recv(min(4096, payload_length - bytes_received))
            if not chunk:
                print(f"Connection closed before receiving all data: got {bytes_received} of {payload_length} bytes")
                sys.exit(1)
            payload += chunk
            bytes_received += len(chunk)
        
        client_sock.close()
        
        # Decrypt the session key
        print("Decrypting session key...")
        session_key = decrypt_session_key(session_key_b64, private_key)
        
        # Decrypt the payload
        print("Decrypting payload...")
        decrypted_payload = decrypt_payload(payload, session_key)
        
        # Write to output file
        output_path = Path(args.output)
        output_path.write_bytes(decrypted_payload)
        print(f"Decrypted payload written to {args.output}")
        
    except socket.timeout:
        print(f"Timeout waiting for connection after {args.timeout} seconds")
        sys.exit(1)


if __name__ == "__main__":
    main()