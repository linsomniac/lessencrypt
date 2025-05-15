#!/usr/bin/env python
"""
LessEncrypt Server

Manages client connections, key processing, and certificate generation.
"""

import argparse
import base64
import configparser
import os
import re
import socket
import sys
import threading
from typing import Dict, List, Optional, Tuple, Any
from re import Pattern
from pathlib import Path
import dns.resolver
import dns.reversename
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from jinja2 import Template
import datetime

DEFAULT_PORT = 334
DEFAULT_TIMEOUT = 60
DEFAULT_CONFIG_FILE = "/etc/lessencrypt/config.ini"
DEFAULT_MAPPING_FILE = "/etc/lessencrypt/name_mapping.conf"


class ServerConfig:
    """Server configuration."""

    def __init__(self, config_file: Path) -> None:
        """Initialize server configuration from a file."""
        config = configparser.ConfigParser()
        config.read(config_file)

        self.listen_address = config.get("server", "listen_address", fallback="0.0.0.0")
        self.port = config.getint("server", "port", fallback=DEFAULT_PORT)
        self.timeout = config.getint("server", "timeout", fallback=DEFAULT_TIMEOUT)

        self.ca_cert_file = Path(config.get("ca", "cert_file"))
        self.ca_key_file = Path(config.get("ca", "key_file"))
        self.ca_key_password = config.get("ca", "key_password", fallback=None)

        self.cert_country = config.get("certificate", "country", fallback="US")
        self.cert_state = config.get("certificate", "state", fallback="California")
        self.cert_locality = config.get(
            "certificate", "locality", fallback="San Francisco"
        )
        self.cert_organization = config.get(
            "certificate", "organization", fallback="LessEncrypt"
        )
        self.cert_validity_days = config.getint(
            "certificate", "validity_days", fallback=365
        )

        self.name_mapping_file = Path(
            config.get("mapping", "file", fallback=DEFAULT_MAPPING_FILE)
        )


def load_ca_cert_and_key(
    config: ServerConfig,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Load the CA certificate and private key."""
    with open(config.ca_cert_file, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    with open(config.ca_key_file, "rb") as f:
        if config.ca_key_password:
            password = config.ca_key_password.encode()
        else:
            password = None
        ca_key = serialization.load_pem_private_key(f.read(), password=password)

    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise TypeError("CA key is not an RSA private key")

    return ca_cert, ca_key


def parse_name_mapping(mapping_file: Path) -> List[Tuple[Pattern[str], str]]:
    """Parse the name mapping file."""
    mappings = []
    with open(mapping_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Extract the regex and template parts
            match = re.match(r"^/(.*)/\s+(.*)$", line)
            if not match:
                print(f"Invalid mapping line: {line}", file=sys.stderr)
                continue

            regex_str, template_str = match.groups()
            try:
                regex = re.compile(regex_str)
                mappings.append((regex, template_str))
            except re.error as e:
                print(f"Invalid regex in mapping: {regex_str} - {e}", file=sys.stderr)

    return mappings


def lookup_reverse_dns(ip_address: str) -> Optional[str]:
    """Look up the reverse DNS of an IP address."""
    try:
        addr = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(addr, "PTR")
        return str(answers[0]).rstrip(".")
    except Exception as e:
        print(f"Reverse DNS lookup failed for {ip_address}: {e}", file=sys.stderr)
        return None


def match_hostname(
    hostname: str, mappings: List[Tuple[Pattern[str], str]]
) -> Optional[List[str]]:
    """Match a hostname against the name mappings."""
    # Parse hostname into components
    parts = hostname.split(".")
    if len(parts) >= 2:
        host = parts[0]
        domain = ".".join(parts[1:])
    else:
        host = hostname
        domain = ""

    context = {
        "fqdn": hostname,
        "ip": "",  # Will be filled by the caller
        "host": host,
        "domain": domain,
    }

    # Try to match the hostname against the mappings
    for regex, template_str in mappings:
        if regex.search(hostname):
            # Render the template
            template = Template(template_str)
            rendered = template.render(**context)
            return rendered.split()

    return None


def generate_session_key() -> bytes:
    """Generate a random AES-256 session key."""
    return os.urandom(32)  # 256 bits


def generate_certificate(
    public_key_pem: bytes,
    common_name: str,
    sans: List[str],
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    config: ServerConfig,
) -> x509.Certificate:
    """Generate a new certificate signed by the CA."""
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Public key is not an RSA public key")

    # Create the certificate
    builder = x509.CertificateBuilder()  # type: ignore

    # Set the subject
    builder = builder.subject_name(
        x509.Name(
            [  # type: ignore
                x509.NameAttribute(NameOID.COUNTRY_NAME, config.cert_country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.cert_state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, config.cert_locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.cert_organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
    )

    # Set the issuer (from the CA)
    builder = builder.issuer_name(ca_cert.subject)

    # Generate a random serial number
    builder = builder.serial_number(x509.random_serial_number())

    # Set validity period
    now = datetime.datetime.utcnow()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(
        now + datetime.timedelta(days=config.cert_validity_days)
    )

    # Set the public key
    builder = builder.public_key(public_key)

    # Add extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    builder = builder.add_extension(
        x509.ExtendedKeyUsage(
            [
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]
        ),
        critical=False,
    )

    # Add Subject Alternative Names (SANs)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in sans]),
            critical=False,
        )

    # Sign the certificate with the CA key
    certificate = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )

    return certificate


def encrypt_payload(
    session_key: bytes, payload: bytes, client_public_key: rsa.RSAPublicKey
) -> bytes:
    """Encrypt the payload with the session key and encrypt the session key with the client's public key."""
    # Encrypt the session key
    encrypted_session_key = client_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Generate a random IV
    iv = os.urandom(16)

    # Add PKCS#7 padding to payload
    block_size = 16
    padding_length = block_size - (len(payload) % block_size)
    padded_payload = payload + bytes([padding_length] * padding_length)

    # Encrypt the payload with AES-CBC
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()  # type: ignore
    encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()

    # Combine encrypted session key, IV, and encrypted payload
    return bytes(encrypted_session_key + iv + encrypted_payload)


def handle_client(
    client_socket: socket.socket,
    client_address: Tuple[str, int],
    config: ServerConfig,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    mappings: List[Tuple[Pattern[str], str]],
) -> None:
    """Handle a client connection."""
    client_ip = client_address[0]

    try:
        # Look up reverse DNS
        hostname = lookup_reverse_dns(client_ip)
        if not hostname:
            client_socket.sendall(b"error msg=Failed to resolve hostname\n")
            return

        # Match hostname against mappings
        cert_names = match_hostname(hostname, mappings)
        if not cert_names:
            client_socket.sendall(
                f"error msg=No mapping found for {hostname}\n".encode()
            )
            return

        common_name = cert_names[0]
        sans = cert_names[1:]

        # Read the key request
        data = client_socket.recv(8192).decode()
        if not data.startswith("keyreq v=1 pubkey="):
            client_socket.sendall(b"error msg=Invalid key request format\n")
            return

        # Extract the public key
        pubkey_b64 = data.split("pubkey=")[1].strip()
        try:
            pubkey_pem = base64.b64decode(pubkey_b64)
            client_public_key = serialization.load_pem_public_key(pubkey_pem)
            if not isinstance(client_public_key, rsa.RSAPublicKey):
                raise TypeError("Public key is not an RSA public key")
        except Exception as e:
            client_socket.sendall(f"error msg=Invalid public key: {e}\n".encode())
            return

        # Send acknowledgment
        client_socket.sendall(b"ok\n")
        client_socket.close()

        # Generate a certificate
        certificate = generate_certificate(
            pubkey_pem, common_name, sans, ca_cert, ca_key, config
        )

        # Serialize the certificate
        cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)

        # Generate a session key
        session_key = generate_session_key()

        # Encrypt the payload
        encrypted_payload = encrypt_payload(session_key, cert_bytes, client_public_key)

        # Connect back to the client
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(config.timeout)
            sock.connect((hostname, config.port))

            # Send the certificate
            sock.sendall(f"cert v=1 payloadlength={len(encrypted_payload)}\n".encode())
            sock.sendall(encrypted_payload)

    except Exception as e:
        print(f"Error handling client {client_ip}: {e}", file=sys.stderr)
        try:
            client_socket.sendall(f"error msg={str(e)}\n".encode())
        except:
            pass


def main() -> int:
    """Main function for the LessEncrypt server."""
    parser = argparse.ArgumentParser(description="LessEncrypt Server")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_FILE,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--listen", help="IP address to listen on (overrides config file)"
    )
    parser.add_argument(
        "--port", type=int, help="Port to listen on (overrides config file)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Connection timeout in seconds (overrides config file)",
    )
    args = parser.parse_args()

    try:
        # Load configuration
        config = ServerConfig(args.config)

        # Apply command-line overrides
        if args.listen:
            config.listen_address = args.listen
        if args.port:
            config.port = args.port
        if args.timeout:
            config.timeout = args.timeout

        # Load CA certificate and key
        ca_cert, ca_key = load_ca_cert_and_key(config)

        # Parse name mappings
        mappings = parse_name_mapping(config.name_mapping_file)

        # Create the server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((config.listen_address, config.port))
        server_socket.listen(5)

        print(f"Server listening on {config.listen_address}:{config.port}")

        while True:
            # Accept client connections
            client_socket, client_address = server_socket.accept()
            client_socket.settimeout(config.timeout)

            # Handle the client in a new thread
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, config, ca_cert, ca_key, mappings),
            )
            thread.daemon = True
            thread.start()

    except KeyboardInterrupt:
        print("Server stopped by user", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"Server error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
