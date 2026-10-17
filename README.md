# Lab 5 — Cryptography Application

A Python command-line application demonstrating secure cryptographic practices.

## Features

- **Argon2id:** hashes passwords and verifies password attempts without storing plaintext passwords.
- **AES-GCM:** encrypts files and authenticates encrypted data.
- **scrypt:** derives an encryption key from a password.
- **Tampering protection:** rejects modified ciphertext.
- **Wrong-password protection:** rejects incorrect decryption passwords.

## Requirements

- Python 3
- Dependencies listed in `requirements.txt`

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the application

Show available commands:

```bash
python app.py --help
```

Hash a password:

```bash
python app.py hash
```

Verify a password against a hash:

```bash
python app.py verify '<ARGON2ID_HASH>'
```

Encrypt a file:

```bash
python app.py encrypt sample.txt encrypted.bin
```

Decrypt a file:

```bash
python app.py decrypt encrypted.bin decrypted.txt
```

The application prompts for passwords interactively.

## Run tests

```bash
python -m unittest -v
```

The project includes tests for encryption/decryption, password hashing and verification, tampering detection, and incorrect passwords.

## Open-source software evaluation: age

The project also evaluates **age**, an open-source file encryption utility.

Example test:

```bash
age --version
diff sample.txt sample-restored.txt
```

The version check confirmed `age v1.3.2`. The empty output from `diff` confirmed that the restored file matched the original.

## Cryptographic use cases

1. **Password storage:** Argon2id produces a password hash for later verification.
2. **File protection:** AES-GCM provides confidentiality and integrity; scrypt derives the encryption key from a password.
3. **Practical tool evaluation:** age demonstrates file encryption using an existing open-source utility.

## Files

- `app.py` — command-line application
- `test_app.py` — automated tests
- `requirements.txt` — Python dependencies
- `REPORT_LAB5_RU.md` — detailed lab report in Russian
