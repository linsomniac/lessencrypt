#!/usr/bin/env python
"""
LessEncrypt Client

Handles key generation, server connection, and payload decryption.
"""

import argparse
import base64
import socket
import sys
from typing import Optional, Tuple
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_PORT = 334
DEFAULT_TIMEOUT = 60
DEFAULT_KEY_SIZE = 4096


def generate_keypair(
    key_size: int = DEFAULT_KEY_SIZE,
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA key pair with the specified key size."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_base64(public_key: rsa.RSAPublicKey) -> str:
    """Serialize the public key to base64."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode("ascii")


def start_listener(port: int) -> socket.socket:
    """Start listening on the specified port."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(1)
    return listener


def connect_to_server(
    server_address: str, port: int, pubkey_b64: str, timeout: int
) -> bool:
    """Connect to the server and send the public key."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server_address, port))

            # Send the key request
            message = f"keyreq v=1 pubkey={pubkey_b64}\n"
            sock.sendall(message.encode())

            # Wait for server response
            response = sock.recv(1024).decode().strip()

            if response == "ok":
                return True
            elif response.startswith("error msg="):
                error_msg = response[10:]  # Skip "error msg="
                print(f"Server error: {error_msg}", file=sys.stderr)
                return False
            else:
                print(f"Unexpected server response: {response}", file=sys.stderr)
                return False
    except Exception as e:
        print(f"Connection error: {e}", file=sys.stderr)
        return False


def wait_for_certificate(
    listener: socket.socket,
    timeout: int,
    private_key: rsa.RSAPrivateKey,
    output_file: Path,
) -> bool:
    """Wait for a certificate from the server and decrypt it."""
    listener.settimeout(timeout)
    try:
        conn, addr = listener.accept()
        with conn:
            # Read the certificate header
            header = conn.recv(1024).decode()
            if not header.startswith("cert v=1 payloadlength="):
                print("Invalid certificate header", file=sys.stderr)
                return False

            # Parse the payload length
            payload_length_str = header.split("payloadlength=")[1].split("\n")[0]
            payload_length = int(payload_length_str)

            # Read the payload
            payload = b""
            remaining = payload_length
            while remaining > 0:
                chunk = conn.recv(min(4096, remaining))
                if not chunk:
                    break
                payload += chunk
                remaining -= len(chunk)

            if len(payload) != payload_length:
                print(
                    f"Incomplete payload: got {len(payload)} bytes, expected {payload_length}",
                    file=sys.stderr,
                )
                return False

            # The first part of the payload is the encrypted session key
            # The rest is the encrypted certificate
            # We'll assume the first 512 bytes are the encrypted session key
            encrypted_session_key = payload[:512]
            encrypted_payload = payload[512:]

            # Decrypt the session key
            session_key = private_key.decrypt(
                encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Decrypt the payload using the session key
            # Assume the first 16 bytes of the encrypted payload are the IV
            iv = encrypted_payload[:16]
            ciphertext = encrypted_payload[16:]

            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
            decryptor = cipher.decryptor()  # type: ignore
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS#7 padding
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]

            # Write the decrypted payload to the output file
            output_file.write_bytes(decrypted)
            return True
    except socket.timeout:
        print(
            f"Timed out waiting for certificate after {timeout} seconds",
            file=sys.stderr,
        )
        return False
    except Exception as e:
        print(f"Error receiving certificate: {e}", file=sys.stderr)
        return False


def main() -> int:
    """Main function for the LessEncrypt client."""
    parser = argparse.ArgumentParser(description="LessEncrypt Client")
    parser.add_argument("server_address", help="Address of the LessEncrypt server")
    parser.add_argument(
        "output_file", type=Path, help="File to write the decrypted payload to"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Port to connect to (default: 334)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--key-size",
        type=int,
        default=DEFAULT_KEY_SIZE,
        help="RSA key size in bits (default: 4096)",
    )
    args = parser.parse_args()

    # Generate RSA key pair
    print("Generating RSA key pair...")
    private_key, public_key = generate_keypair(args.key_size)
    pubkey_b64 = public_key_to_base64(public_key)

    # Start listening for the certificate
    print(f"Starting listener on port {args.port}...")
    listener = start_listener(args.port)

    try:
        # Connect to the server and send the public key
        print(f"Connecting to server {args.server_address}:{args.port}...")
        if not connect_to_server(
            args.server_address, args.port, pubkey_b64, args.timeout
        ):
            return 1

        # Wait for the certificate
        print("Waiting for certificate...")
        if not wait_for_certificate(
            listener, args.timeout, private_key, args.output_file
        ):
            return 1

        print(f"Certificate saved to {args.output_file}")
        return 0
    finally:
        listener.close()


if __name__ == "__main__":
    sys.exit(main())
