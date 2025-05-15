# LessEncrypt

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

A lightweight, secure certificate management system for internal networks, inspired by Let's Encrypt but designed for self-signed certificates and internal PKI.

## 🔑 Overview

LessEncrypt simplifies certificate management for internal systems by providing an automated way to issue and deploy SSL/TLS certificates signed by your own Certificate Authority (CA). This is ideal for development environments, internal services, and private networks where public CA-signed certificates aren't necessary.

### Key Features

- **Automated Certificate Issuance** - Request and receive certificates with a simple command
- **Secure Key Exchange** - Uses public key cryptography for secure certificate delivery
- **Hostname-Based Mapping** - Flexible hostname-to-certificate mapping via regex patterns
- **Security Hardening** - Protection against connections to unprivileged ports
- **Simple Deployment** - Easy to integrate with web servers like Apache and Nginx

## 📋 Requirements

- Python 3.12 or newer
- Dependencies are managed via uv script mechanism:
  - cryptography
  - jinja2
  - dnspython

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/lessencrypt.git
   cd lessencrypt
   ```

2. Copy and modify the configuration files:
   ```bash
   sudo mkdir -p /etc/lessencrypt
   sudo cp config.ini.example /etc/lessencrypt/config.ini
   sudo cp name_mapping.conf.example /etc/lessencrypt/name_mapping.conf
   ```

3. Configure your CA certificate and key:
   ```bash
   # Generate a new CA (if you don't already have one):
   openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt
   
   # Update paths in config.ini to point to your CA files
   ```

4. Update the hostname mappings in the mapping file.

## 🛠️ Usage

### Server (lessencryptserver)

The server signs certificate requests and delivers them to clients.

```bash
./lessencryptserver [--config CONFIG_PATH] [--listen IP] [--port PORT] [--timeout SECONDS] [--verbose] [--debug]
```

Options:
- `--config`: Path to configuration file (default: /etc/lessencrypt/config.ini)
- `--listen`: IP address to listen on (overrides config file)
- `--port`: Port to listen on (overrides config file)
- `--timeout`: Connection timeout in seconds (overrides config file)
- `--verbose`: Enable verbose logging (INFO level)
- `--debug`: Enable debug logging (DEBUG level)

### Client (lessencryptcli)

The client requests and receives certificates signed by the server's CA.

```bash
./lessencryptcli SERVER_ADDRESS OUTPUT_FILE [--port PORT] [--timeout SECONDS] [--key-size BITS] [--passphrase PASSPHRASE]
```

Options:
- `SERVER_ADDRESS`: Address of the LessEncrypt server (with optional port: hostname:port)
- `OUTPUT_FILE`: Path to save the certificate
- `--port`: Port to connect to (default: 334)
- `--timeout`: Timeout in seconds (default: 60)
- `--key-size`: RSA key size in bits (default: 4096)
- `--passphrase`: Optional passphrase to encrypt the private key

## 🔒 Protocol Flow

1. Client generates an RSA key pair
2. Client connects to server and sends public key
3. Server validates the client (using reverse DNS and name mappings)
4. Server generates a certificate, signed by its CA
5. Server establishes a return connection to client
6. Server sends the encrypted certificate
7. Client decrypts and saves both certificate and private key
8. Certificate can now be used with web servers or other services

## 🛡️ Security Features

- **Client Verification**: Uses reverse DNS to verify client identity
- **Port Security**: By default, refuses connections to unprivileged ports (>= 1024)
- **Encrypted Transport**: All certificate data is encrypted using AES-256
- **Private Key Protection**: Optional passphrase encryption for private keys
- **Customizable Certificate Attributes**: Full control over certificate properties

## 📝 Configuration

### Server Configuration (config.ini)

The server configuration file controls all aspects of certificate generation:

```ini
[server]
listen_address = 0.0.0.0
port = 334
timeout = 60
allow_high_ports = false
mappings = /etc/lessencrypt/name_mapping.conf
ca_cert_file = /etc/lessencrypt/ca.crt
ca_key_file = /etc/lessencrypt/ca.key
# ca_key_password = your-secure-password

[certificate]
country = US
state = California
locality = San Francisco
organization = YourOrganization
validity_days = 365
```

### Name Mapping (name_mapping.conf)

This file defines regex patterns that map hostnames to certificate common names and subject alternative names:

```
# Format: /regex_pattern/ template
/^([\w-]+)\.example\.com$/ {{ host }}.example.com
/^([\w-]+)\.internal$/ {{ host }}.internal {{ host }}.example.com
```

## 🔄 Integration Examples

### Apache

```apache
SSLEngine on
SSLCertificateFile /path/to/certificate.crt
SSLCertificateKeyFile /path/to/certificate.key
```

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/certificate.key;
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.