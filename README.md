# LessEncrypt

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-CC0-green.svg)](LICENSE)

</div>

> **An ultra-lightweight, no-hassle alternative to Let's Encrypt—built for self-signed certs like in homelabs and dev environments.**

LessEncrypt is a minimalist certificate management tool for environments where full
ACME infrastructure is overkill. Designed with simplicity and self-signed CAs in mind,
LessEncrypt handles certificate updates and skips all the complexity you don’t need.

No HTTP challenges. No domain validation hoops. No HTTP port wrangling. Just your certs, on your terms.

## 🔑 Overview

LessEncrypt simplifies certificate management for internal systems by providing an automated way to issue and deploy SSL/TLS certificates signed by your own Certificate Authority (CA). This is ideal for development environments, internal services, and private networks where public CA-signed certificates aren't necessary.

Like LetsEncrypt/ACME, LessEncrypt uses a socket in the <1024 range to validate that a request is coming
from a "responsible party". It then delivers a signed certificate back to that system in a secure way,
preventing interception. Reverse DNS is used to determine what names are allowed for the cert to be issued
to.

### ✨ Key Features

- **Automated Certificate Issuance** - Request and receive certificates with a simple command
- **Secure Key Exchange** - Uses public key cryptography for secure certificate delivery
- **Reverse DNS-Based Mapping** - Flexible hostname-to-certificate mapping via regex patterns
- **Security Hardening** - Protection against replay and DoS attacks via an optional shared secret
- **Simple Deployment** - Easy to integrate with web servers like Apache and Nginx
- **No HTTP Port Takover** - No need to publish a WKS on the HTTP port
- **Runs Post-Cert Scripts** - Scripts to post-process or load certs, restart web servers, etc
- **Smart Certificate Renewal** - Can update certs only when previous cert is about to expire

## 📋 Requirements

- Python 3.12 or newer
- Dependencies are managed via uv script mechanism:
  - cryptography
  - jinja2
  - dnspython
- Reverse DNS mappings for hosts
- Port 334/tcp open on client and server (can be configured, <1024 recommended)

## ⚙️ Overview

LessEncrypt uses the reverse DNS of a connecting host, plus a "mapping" configuration
file to generate certificates, controlling CNs and SANs on the cert. Any reverse resolution
can be used, for example an /etc/hosts file on the machine running LessEncrypt.

The client connects in and sends a public key. The server generates a certificate based
on the reverse DNS, connects back to the client and delivers the signed cert. The
connection back to a well known <1024 port is how it ensures the client identity.

## 🚀 Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/lessencrypt.git
   cd lessencrypt
   ```

2. Copy and modify the configuration files:

   ```bash
   sudo mkdir -p /etc/lessencrypt
   sudo cp lessencrypt.conf.example /etc/lessencrypt/lessencrypt.conf
   sudo cp name_mapping.conf.example /etc/lessencrypt/name_mapping.conf
   ```

3. Configure your CA certificate and key:

   ```bash
   # Generate a new CA (if you don't already have one):
   openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt
   #  Ensure your ca.key is mode 600 to protect it:
   chmod 600 ca.key

   # Update paths in config.ini to point to your CA files
   ```

4. Update the hostname mappings in the mapping file.

5. Run "lessencryptserver". A "systemd" file is provided.

## 🛠️ Usage

### Server (lessencryptserver)

The server signs certificate requests and delivers them to clients.

```bash
usage: lessencryptserver [-h] [--config CONFIG] [--listen LISTEN] [--port PORT] [--timeout TIMEOUT] [--verbose]
                         [--debug] [--test-mappings]
                         [hostnames ...]
```

Options:

- `--config`: Path to configuration file (default: /etc/lessencrypt/lessencrypt.conf)
- `--listen`: IP address to listen on (overrides config file)
- `--port`: Port to listen on (overrides config file)
- `--timeout`: Connection timeout in seconds (overrides config file)
- `--verbose`: Enable verbose logging (INFO level)
- `--debug`: Enable debug logging (DEBUG level)
- `--test-mappings`: Test hostname mappings instead of running server, list
  hostnames to test on the command line

### Client (lessencryptcli)

The client requests and receives certificates signed by the server's CA.

```bash
usage: lessencryptcli [-h] [--config CONFIG] [--port PORT] [--timeout TIMEOUT] [--key-size KEY_SIZE]
       [--key-password KEY_PASSWORD] [--key-file KEY_FILE] [--ca-file CA_FILE] [--post-renew POST_RENEW]
       [--renew-within-days RENEW_WITHIN_DAYS] [--shared-secret SHARED_SECRET]
       [server_address] [output_file]
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
6. Server sends the certificate (unencrypted as it's public information)
7. Client saves both certificate and private key
8. Certificate can now be used with web servers or other services

## 🛡️ Security Features

- **Client Verification**: Uses reverse DNS to verify client identity
- **Port Security**: By default, refuses connections to unprivileged ports (>= 1024)
- **Encrypted Transport**: All certificate data is encrypted using AES-256
- **Private Key Protection**: Optional passphrase encryption for private keys
- **Customizable Certificate Attributes**: Full control over certificate properties

## 📝 Configuration

### Server Configuration (lessencrypt.conf)

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

## ❌ Revoking/Expiring Certs

The `expire-certs` script can be used on the `certs.txt` file written by the server to
find certs that have been reissued and mark them as "R" for revoked, and also it will
remove from the file any certs that are past their expiry date.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is released under the [CC0 1.0 Universal (Public Domain Dedication)](https://creativecommons.org/publicdomain/zero/1.0/).  
Use it. Fork it. Rewrite it. No attribution necessary.
