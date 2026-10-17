"""Mini cryptography demo for Lab 5: Argon2id password hashing and AES-GCM file encryption."""
from __future__ import annotations
import argparse
import base64
import getpass
import json
import os
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

PH = PasswordHasher()  # argon2-cffi secure defaults; random salt per hash


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty")
    return PH.hash(password)


def verify_password(encoded_hash: str, password: str) -> bool:
    try:
        return PH.verify(encoded_hash, password)
    except (VerificationError, VerifyMismatchError, ValueError):
        return False


def encrypt_file(source: Path, destination: Path, password: str) -> None:
    """Encrypt bytes with AES-256-GCM; output stores salt, nonce, and ciphertext/tag."""
    if not password:
        raise ValueError("Password must not be empty")
    salt = os.urandom(16)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    # Derive a 256-bit key using scrypt; never store the password or derived key.
    import hashlib
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    plaintext = source.read_bytes()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"lab5-file-v1")
    envelope = {
        "version": 1,
        "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    destination.write_text(json.dumps(envelope, indent=2), encoding="utf-8")


def decrypt_file(source: Path, destination: Path, password: str) -> None:
    """Authenticate before writing plaintext; wrong password/tampering raises an error."""
    envelope = json.loads(source.read_text(encoding="utf-8"))
    if envelope.get("version") != 1 or envelope.get("kdf") != "scrypt":
        raise ValueError("Unsupported encrypted file format")
    salt = base64.b64decode(envelope["salt"], validate=True)
    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("Invalid salt or nonce length")
    import hashlib
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, b"lab5-file-v1")
    except InvalidTag as exc:
        raise ValueError("Authentication failed: wrong password or modified file") from exc
    destination.write_bytes(plaintext)


def main():
    parser = argparse.ArgumentParser(description="Lab 5 cryptography demonstration")
    sub = parser.add_subparsers(dest="command", required=True)

    hp = sub.add_parser("hash", help="hash a password using Argon2id")
    hp.add_argument("--password", help="demo only; interactive prompt is safer")

    vp = sub.add_parser("verify", help="verify a password against an Argon2id hash")
    vp.add_argument("encoded_hash")
    vp.add_argument("--password")

    enc = sub.add_parser("encrypt", help="encrypt a file using AES-GCM")
    enc.add_argument("input", type=Path)
    enc.add_argument("output", type=Path)

    dec = sub.add_parser("decrypt", help="decrypt and authenticate a file")
    dec.add_argument("input", type=Path)
    dec.add_argument("output", type=Path)

    args = parser.parse_args()
    if args.command == "hash":
        password = args.password if args.password is not None else getpass.getpass("Password: ")
        print(hash_password(password))
    elif args.command == "verify":
        password = args.password if args.password is not None else getpass.getpass("Password: ")
        print("MATCH" if verify_password(args.encoded_hash, password) else "NO MATCH")
    elif args.command == "encrypt":
        encrypt_file(args.input, args.output, getpass.getpass("Encryption password: "))
        print(f"Encrypted file written to {args.output}")
    elif args.command == "decrypt":
        decrypt_file(args.input, args.output, getpass.getpass("Decryption password: "))
        print(f"Decrypted file written to {args.output}")


if __name__ == "__main__":
    main()
