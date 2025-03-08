# FileCrypter

A secure file encryption tool that uses modern cryptographic techniques to protect your files and directories.

## Features

- **File Encryption/Decryption**: Securely encrypt individual files using industry-standard AES encryption
- **Directory Encryption**: Package and encrypt entire directories while preserving structure
- **Digital Signatures**: Sign and verify files to ensure authenticity
- **Key Management**: Generate, import, export, and manage cryptographic keys
- **Smart Detection**: Automatically detects file types and operations needed
- **Interactive Mode**: User-friendly menu-driven interface
- **CLI Support**: Command-line interface for automation and scripting

## Installation

```bash
# Clone the repository
git clone https://github.com/Muddyblack/filecrypter.git
cd filecrypter

# Install dependencies
pip install -e .
```

## Quick Start

### Interactive Mode
Simply run the program without arguments to enter interactive mode:

```bash
python main.py
```

or if installed:

```bash
filecrypter
#or
sfc
```


## Security Features

- AES-GCM for file encryption
- RSA-3072 for key operations
- Scrypt key derivation for password-based encryption
- Digital signatures for file integrity verification
- Secure key storage and management

## Key Management

The application supports:
- Generating new RSA keypairs
- Importing trusted public keys
- Exporting your public key
- Managing trusted keys
- Key revocation

## Requirements

- Python 3.6+
- cryptography>=36.0.0
- rich>=12.0.0
- typer>=0.4.0

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## File Formats

- `.sfc`: Encrypted files and directories (Secure File Container)
- `.sig`: Digital signatures
- `.pem`: Cryptographic keys

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - See LICENSE file for details.

## Security Considerations

- Keep your private key secure
- Use strong passwords
- Verify signatures of important files
- Back up your keys safely

## Troubleshooting

### Common Issues

1. **"No private key found"**
   - Generate a new keypair using the key management menu

2. **"Invalid password"**
   - Make sure you're using the correct password
   - For legacy files, try the default empty password

3. **"File appears corrupted"**
   - Verify file integrity
   - Check if it's the correct file format

