import unittest
from typing import Union
from monero.chacha20 import encrypt, decrypt, CryptoError

class TestEncryptionDecryption(unittest.TestCase):

    def setUp(self):
        self.skey = b'0' * 32  # 32-byte key for testing

    def encrypt_decrypt_test(self, plaintext: Union[str, bytes], authenticated: bool = False, kdf_rounds: int = 1):
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        encrypted = encrypt(plaintext, self.skey, authenticated, kdf_rounds)
        decrypted = decrypt(encrypted, self.skey, authenticated, kdf_rounds)
        
        self.assertEqual(plaintext_bytes, decrypted)

    def test_basic_encryption_decryption(self):
        self.encrypt_decrypt_test("Hello, World!")

    def test_authenticated_encryption_decryption(self):
        self.encrypt_decrypt_test("Authenticated message", authenticated=True)

    def test_empty_string(self):
        self.encrypt_decrypt_test("")

    def test_binary_data(self):
        self.encrypt_decrypt_test(b'\x00\x01\x02\x03\x04')

    def test_long_text(self):
        long_text = "A" * 1000
        self.encrypt_decrypt_test(long_text)

    def test_multiple_kdf_rounds(self):
        self.encrypt_decrypt_test("Multiple KDF rounds", kdf_rounds=1000)

    def test_authenticated_with_multiple_kdf_rounds(self):
        self.encrypt_decrypt_test("Authenticated with multiple KDF rounds", authenticated=True, kdf_rounds=1000)

    def test_wrong_key_fails(self):
        plaintext = "Secret message"
        encrypted = encrypt(plaintext, self.skey)
        wrong_key = b'1' * 32
        with self.assertRaises(CryptoError):
            decrypt(encrypted, wrong_key)

    def test_tampered_ciphertext_fails(self):
        plaintext = "Don't tamper with me"
        encrypted = encrypt(plaintext, self.skey, authenticated=True)
        tampered = bytearray(encrypted)
        tampered[15] ^= 1  # Flip one bit
        with self.assertRaises(CryptoError):
            decrypt(bytes(tampered), self.skey, authenticated=True)

    def test_wrong_authenticated_mode_fails(self):
        plaintext = "Authenticate me correctly"
        encrypted = encrypt(plaintext, self.skey, authenticated=True)
        with self.assertRaises(CryptoError):
            decrypt(encrypted, self.skey, authenticated=False)

    def test_invalid_inputs(self):
        with self.assertRaises(CryptoError):
            encrypt(123, self.skey)  # Invalid plaintext type
        with self.assertRaises(CryptoError):
            encrypt("Valid text", b'short_key')  # Invalid key length
        with self.assertRaises(CryptoError):
            encrypt("Valid text", self.skey, authenticated="not a bool")  # Invalid authenticated flag
        with self.assertRaises(CryptoError):
            encrypt("Valid text", self.skey, kdf_rounds=0)  # Invalid KDF rounds

    def test_decryption_invalid_inputs(self):
        valid_encrypted = encrypt("Valid text", self.skey)
        with self.assertRaises(CryptoError):
            decrypt("not bytes", self.skey)  # Invalid ciphertext type
        with self.assertRaises(CryptoError):
            decrypt(valid_encrypted, b'short_key')  # Invalid key length
        with self.assertRaises(CryptoError):
            decrypt(valid_encrypted, self.skey, authenticated="not a bool")  # Invalid authenticated flag
        with self.assertRaises(CryptoError):
            decrypt(valid_encrypted, self.skey, kdf_rounds=0)  # Invalid KDF rounds
        with self.assertRaises(CryptoError):
            decrypt(b'', self.skey)  # Ciphertext too short

if __name__ == '__main__':
    unittest.main()
