import nacl.utils
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.secret import SecretBox
from nacl.pwhash import argon2i

def generate_identity_keypair():
    sk = PrivateKey.generate()
    pk = sk.public_key
    return sk, pk

def encrypt_private_keys(private_bytes: bytes, password: str) -> bytes:
    salt = nacl.utils.random(16)
    key = argon2i.kdf(32, password.encode(), salt)
    box = SecretBox(key)
    encrypted = box.encrypt(private_bytes)
    return salt + encrypted

def decrypt_private_keys(bundle: bytes, password: str) -> bytes:
    salt = bundle[:16]
    ciphertext = bundle[16:]
    key = argon2i.kdf(32, password.encode(), salt)
    box = SecretBox(key)
    return box.decrypt(ciphertext)

def envelope_for_recipient(data_key: bytes, recipient_pk_hex: str) -> bytes:
    recipient_pk = PublicKey(bytes.fromhex(recipient_pk_hex))
    box = SealedBox(recipient_pk)
    return box.encrypt(data_key)

def open_envelope(encrypted: bytes, private_key: PrivateKey) -> bytes:
    box = SealedBox(private_key)
    return box.decrypt(encrypted)
