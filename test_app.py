import json
import tempfile
import unittest
from pathlib import Path

from app import hash_password, verify_password, encrypt_file, decrypt_file


class CryptoAppTests(unittest.TestCase):
    def test_argon2_password_hash_and_verify(self):
        h1 = hash_password("Strong-demo-password-2026!")
        h2 = hash_password("Strong-demo-password-2026!")
        self.assertNotEqual(h1, h2)  # random salt
        self.assertTrue(verify_password(h1, "Strong-demo-password-2026!"))
        self.assertFalse(verify_password(h1, "wrong-password"))

    def test_aes_gcm_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "message.txt"
            encrypted = root / "message.enc.json"
            decrypted = root / "restored.txt"
            original.write_bytes(b"Confidential demo content")
            encrypt_file(original, encrypted, "test-encryption-password")
            decrypt_file(encrypted, decrypted, "test-encryption-password")
            self.assertEqual(original.read_bytes(), decrypted.read_bytes())

    def test_wrong_password_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, encrypted, decrypted = root / "a.txt", root / "a.enc", root / "out.txt"
            original.write_text("secret", encoding="utf-8")
            encrypt_file(original, encrypted, "correct-password")
            with self.assertRaises(ValueError):
                decrypt_file(encrypted, decrypted, "incorrect-password")
            self.assertFalse(decrypted.exists())

    def test_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, encrypted, decrypted = root / "a.txt", root / "a.enc", root / "out.txt"
            original.write_text("secret", encoding="utf-8")
            encrypt_file(original, encrypted, "correct-password")
            obj = json.loads(encrypted.read_text())
            obj["ciphertext"] = obj["ciphertext"][:-4] + "AAAA"
            encrypted.write_text(json.dumps(obj))
            with self.assertRaises(ValueError):
                decrypt_file(encrypted, decrypted, "correct-password")
            self.assertFalse(decrypted.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
