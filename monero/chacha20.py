from os import urandom
from typing import Union
from Cryptodome.Cipher import ChaCha20
from nacl.bindings import crypto_sign_keypair, crypto_sign
from nacl.utils import random
from nacl.exceptions import CryptoError
from .keccak import keccak_256

class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass

def generate_chacha_key(skey: bytes, kdf_rounds: int) -> bytes:
    if not isinstance(skey, bytes) or len(skey) != 32:
        raise ValueError("Secret key must be 32 bytes")
    if not isinstance(kdf_rounds, int) or kdf_rounds < 1:
        raise ValueError("KDF rounds must be a positive integer")
    
    key = skey
    for _ in range(kdf_rounds):
        key = keccak_256(key).digest()
    return key[:32]  # Return only the first 32 bytes

def encrypt(plaintext: Union[bytes, str], skey: bytes, authenticated: bool = False, kdf_rounds: int = 1) -> bytes:
    try:
        # Input validation
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        elif not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes or str")
        
        if not isinstance(skey, bytes) or len(skey) != 32:
            raise ValueError("Secret key must be 32 bytes")
        
        if not isinstance(authenticated, bool):
            raise TypeError("Authenticated must be a boolean")
        
        if not isinstance(kdf_rounds, int) or kdf_rounds < 1:
            raise ValueError("KDF rounds must be a positive integer")

        # Generate ChaCha20 key
        key = generate_chacha_key(skey, kdf_rounds)

        # Generate random nonce (IV)
        nonce = random(8)  # 8 bytes (64 bits) to match the C++ implementation

        # Encrypt the plaintext
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        result = nonce + ciphertext

        if authenticated:
            # Generate keypair for signing
            try:
                public_key, _ = crypto_sign_keypair(skey)
            except CryptoError as e:
                raise EncryptionError(f"Failed to generate keypair: {str(e)}")
            
            # Hash the ciphertext
            hash_obj = keccak_256(result)
            
            # Sign the hash
            try:
                signature = crypto_sign(hash_obj.digest(), skey)[:64]  # Use only the first 64 bytes (signature without message)
            except CryptoError as e:
                raise EncryptionError(f"Failed to sign the hash: {str(e)}")

            result += signature

        return result

    except (ValueError, TypeError) as e:
        raise EncryptionError(f"Input validation error: {str(e)}")
    except Exception as e:
        raise EncryptionError(f"Unexpected error during encryption: {str(e)}")

# Example usage:
if __name__ == "__main__":
    try:
        skey = urandom(32)  # 256-bit secret key
        plaintext = "Hello, World!"
        encrypted = encrypt(plaintext, skey, authenticated=True, kdf_rounds=1)
        print(encrypted.hex())
    except EncryptionError as e:
        print(f"Encryption failed: {str(e)}")
