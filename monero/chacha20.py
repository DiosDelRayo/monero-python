from nacl.utils import random
from typing import Union
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Random import get_random_bytes
from nacl.bindings import crypto_sign, crypto_sign_keypair
from nacl.exceptions import CryptoError
from typing import Optional
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
    raise Exception('Not implemented cn_slow_hash missing!')
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

def decrypt(ciphertext: bytes, skey: bytes, authenticated: bool = False, kdf_rounds: int = 1) -> bytes:
    try:
        if not isinstance(ciphertext, bytes):
            raise TypeError("Ciphertext must be bytes")
        
        if not isinstance(skey, bytes) or len(skey) != 32:
            raise ValueError("Secret key must be 32 bytes")
        
        if not isinstance(authenticated, bool):
            raise TypeError("Authenticated must be a boolean")
        
        if not isinstance(kdf_rounds, int) or kdf_rounds < 1:
            raise ValueError("KDF rounds must be a positive integer")

        if authenticated:
            if len(ciphertext) < (CHACHA_IV_SIZE + 64):  # (iv) + 64 (signature) minimum
                raise ValueError("Ciphertext too short for authenticated mode")
            signature = ciphertext[-64:]
            ciphertext = ciphertext[:-64]
            hash_obj = keccak_256(ciphertext)
            public_key, _ = crypto_sign_keypair(skey)
            try:
                crypto_sign_open(signature + hash_obj.digest(), public_key)
            except CryptoError:
                raise CryptoError("Signature verification failed")

        if len(ciphertext) < (CHACHA_IV_SIZE + 1):  # (iv) + 1 (minimum encrypted data) minimum
            raise ValueError("Ciphertext too short")

        iv = ciphertext[:CHACHA_IV_SIZE]
        encrypted_data = ciphertext[CHACHA_IV_SIZE:]

        key = generate_chacha_key(skey, kdf_rounds)
        cipher = ChaCha20.new(key=key, nonce=iv)
        plaintext = cipher.decrypt(encrypted_data)

        return plaintext

    except (ValueError, TypeError) as e:
        raise CryptoError(f"Decryption error: {str(e)}")
    except Exception as e:
        raise CryptoError(f"Unexpected error during decryption: {str(e)}")
