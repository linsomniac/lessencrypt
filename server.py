#!/usr/bin/env python3
# requires: cryptography pydantic black mypy

import argparse
import base64
import os
import socket
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def load_public_key(pem_data: bytes) -> serialization.PublicKey:
    """Load a public key from PEM data."""
    return serialization.load_pem_public_key(pem_data)


def encrypt_with_public_key(data: bytes, public_key: serialization.PublicKey) -> bytes:
    """Encrypt data with a public key using OAEP padding."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_payload(payload: bytes, session_key: bytes) -> bytes:
    """Encrypt the payload using AES-256-CBC with the session key."""
    # Generate a random IV
    iv = os.urandom(16)
    
    # Pad the payload to a multiple of the block size
    block_size = 16
    padding_length = block_size - (len(payload) % block_size)
    if padding_length == 0:
        padding_length = block_size
    
    padded_payload = payload + bytes([padding_length] * padding_length)
    
    # Encrypt the padded payload
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
    
    # Return IV + ciphertext
    return iv + ciphertext


def main() -> None:
    parser = argparse.ArgumentParser(description="Certificate encryption server")
    parser.add_argument("payload", help="File to encrypt and send as the payload")
    parser.add_argument(
        "--listen", 
        default="0.0.0.0", 
        help="Address to listen on (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=334, 
        help="Port to listen on (default: 334)"
    )
    parser.add_argument(
        "--timeout", 
        type=int, 
        default=60, 
        help="Timeout for connections in seconds"
    )
    args = parser.parse_args()

    # Read the payload file
    payload_path = Path(args.payload)
    if not payload_path.exists():
        print(f"Error: Payload file {args.payload} does not exist")
        return
    
    payload = payload_path.read_bytes()
    print(f"Loaded payload: {len(payload)} bytes")

    # Start listening for connections
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.listen, args.port))
    server_sock.listen(5)
    server_sock.settimeout(args.timeout)
    
    print(f"Server listening on {args.listen}:{args.port}")
    
    try:
        while True:
            try:
                client_sock, addr = server_sock.accept()
                client_addr = f"{addr[0]}:{addr[1]}"
                print(f"Connection from {client_addr}")
                
                # Receive the key request
                data = client_sock.recv(8192).decode()
                if not data.startswith("keyreq v=1 "):
                    print(f"Invalid request from {client_addr}: {data}")
                    client_sock.close()
                    continue
                
                # Extract the public key
                parts = data.strip().split()
                pubkey_b64 = None
                
                for part in parts:
                    if part.startswith("pubkey="):
                        pubkey_b64 = part[len("pubkey="):]
                        break
                
                if pubkey_b64 is None:
                    print(f"Missing public key in request from {client_addr}")
                    client_sock.close()
                    continue
                
                # Decode the public key
                try:
                    pubkey_pem = base64.b64decode(pubkey_b64)
                    public_key = load_public_key(pubkey_pem)
                    
                    # Send acknowledgement
                    client_sock.sendall(b"ok\n")
                    client_sock.close()
                    
                    # Generate a session key
                    session_key = os.urandom(32)  # 256 bits
                    
                    # Encrypt the session key with the client's public key
                    encrypted_session_key = encrypt_with_public_key(session_key, public_key)
                    session_key_b64 = base64.b64encode(encrypted_session_key).decode()
                    
                    # Encrypt the payload with the session key
                    encrypted_payload = encrypt_payload(payload, session_key)
                    
                    # Wait a moment for the client to start listening
                    time.sleep(1)
                    
                    # Connect back to the client
                    print(f"Connecting back to {addr[0]}:{args.port}")
                    back_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    back_sock.connect((addr[0], args.port))
                    
                    # Send the encrypted certificate
                    cert_line = f"cert v=1 sessionkey={session_key_b64} payloadlength={len(encrypted_payload)}\n"
                    back_sock.sendall(cert_line.encode())
                    
                    # Send the encrypted payload
                    back_sock.sendall(encrypted_payload)
                    back_sock.close()
                    
                    print(f"Sent encrypted payload to {addr[0]}:{args.port}")
                    
                except Exception as e:
                    print(f"Error processing request from {client_addr}: {e}")
                    continue
                    
            except socket.timeout:
                continue
                
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()