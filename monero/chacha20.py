from nacl.utils import random
from typing import Union
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Random import get_random_bytes
from nacl.bindings import crypto_sign, crypto_sign_keypair
from nacl.exceptions import CryptoError
from .keccak import keccak_256

CHACHA_IV_SIZE = 8


class EncryptionError(Exception):
    """Encryption issues."""
    pass


def generate_chacha_random_iv(length: Optional[int] = None):
    if length is not None and length not in (8, 12):
        raise ValueError('If length is provided, it must be 8 or 12 bytes for Chacha20')
    return get_random_bytes(length or CHACHA_IV_SIZE)

def generate_chacha_key(skey: bytes, kdf_rounds: int) -> bytes:
    if not isinstance(skey, bytes) or len(skey) != 32:
        raise ValueError("Secret key must be 32 bytes")
    if not isinstance(kdf_rounds, int) or kdf_rounds < 1:
        raise ValueError("KDF rounds must be a positive integer")
    
    key = skey
    for _ in range(kdf_rounds):
        key = keccak_256(key).digest()
    return key[:32]

def encrypt(plaintext: Union[bytes, str], skey: bytes, authenticated: bool = False, kdf_rounds: int = 1) -> bytes:
    try:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        elif not isinstance(plaintext, bytes):
            raise TypeError("Plaintext must be bytes or str")
        
        if not isinstance(skey, bytes) or len(skey) != 32:
            raise ValueError("Secret key must be 32 bytes")
        
        if not isinstance(authenticated, bool):
            raise TypeError("Authenticated must be a boolean")
        
        if not isinstance(kdf_rounds, int) or kdf_rounds < 1:
            raise ValueError("KDF rounds must be a positive integer")

        key = generate_chacha_key(skey, kdf_rounds)
        iv = generate_chacha_random_iv()
        cipher = ChaCha20.new(key=key, nonce=iv)
        ciphertext = iv + cipher.encrypt(plaintext)

        if authenticated:
            hash_obj = keccak_256(ciphertext)
            public_key, _ = crypto_sign_keypair(skey)
            signature = crypto_sign(hash_obj.digest(), skey)[:64]
            ciphertext += signature

        return ciphertext

    except (ValueError, TypeError) as e:
        raise EncryptionError(f"Input validation error: {str(e)}")
    except Exception as e:
        raise EncryptionError(f"Unexpected error during encryption: {str(e)}")
