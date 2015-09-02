import base
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# -----------------------------------------------------------------------------------
# Symmetric cryptography
# -----------------------------------------------------------------------------------
SYM_BLOCK_SIZE = 16

# Padding
def pad(scheme, size: int, message: bytes) -> bytes:
    """
    Pad a byte string L{message} so that it fits snuggly into blocks of bytelength
    L{size} using padding scheme L{scheme}.
    """
    padder = scheme(size*8).padder()
    return padder.update(message) + padder.finalize()

def unpad(scheme, size: int, message: bytes) -> bytes:
    unpadder = scheme(size*8).unpadder()
    return unpadder.update(message) + unpadder.finalize()

# Encryption & decryption
def sym_enc(message: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt a message using AES in counter (CTR) mode with given key and
    initialisation vector.

    Returns the ciphertext as a byte string.
    """
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv),
            backend=default_backend()).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    return ciphertext

def sym_dec(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt a message encrypted under AES in CTR mode with given key and
    initialisation vector.

    Returns the message as a byte string.
    """
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CFB(iv),
                backend=default_backend()).decryptor()

        message = decryptor.update(ciphertext) + decryptor.finalize()

        return message
    except Exception:
        return None

# -----------------------------------------------------------------------------------
# Public-key cryptography
# -----------------------------------------------------------------------------------

# Serialization
def load_pkey(bs: bytes) -> rsa.RSAPublicKey:
    """
    Parse a DER-encoded RSA public key from a byte string.
    """
    pkey = serialization.load_der_public_key(bs, default_backend())
    if not isinstance(pkey, rsa.RSAPublicKey):
        raise Exception('Not an RSA public key')
    return pkey

def serialize_pkey(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encode an RSA public key into the DER format.
    """
    return public_key.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

def load_skey(bs: bytes) -> rsa.RSAPrivateKey:
    """
    Parse a DER-encoded RSA private key from a byte string.
    """
    skey = serialization.load_der_private_key(bs, None, default_backend())
    if not isinstance(skey, rsa.RSAPrivateKey):
        raise Exception('Not an RSA private key')
    return skey

def serialize_skey(private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Serialize an RSA private into the DER format.
    """
    return private_key.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

# Key generation
def pk_keygen(size: int):
    """
    Generate an RSA key pair with modulo of given bitsize.
    """
    key = rsa.generate_private_key(65537, size, default_backend())
    return (key.public_key(), key)

# Encryption & decryption -- RSA OAEP
def pk_enc(message: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt a message using RSAES-OAEP.
    """
    ciphertext = public_key.encrypt(message, padding.OAEP(
            padding.MGF1(hashes.SHA1()),
            hashes.SHA1(),
            None))
    return ciphertext

def pk_dec(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypt an RSAES-OAEP-encrypted message.
    """
    plaintext = private_key.decrypt(ciphertext, padding.OAEP(
            padding.MGF1(hashes.SHA1()),
            hashes.SHA1(),
            None))
    return plaintext

# Digital signatures -- RSA PSS
def pk_sign(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign a message using RSASSA-PSS.
    """
    signer = private_key.signer(padding.PSS(padding.MGF1(hashes.SHA256()),
            padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    signer.update(message)
    return signer.finalize()

def pk_verify(message: bytes, public_key: rsa.RSAPublicKey, signature: bytes) -> bool:
    """
    Verify a message signature created with RSASSA-PSS.
    """
    verifier = public_key.verifier(signature,
        padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    verifier.update(message)

    try:
        verifier.verify()
    except exceptions.InvalidSignature:
        return False
    return True

# -----------------------------------------------------------------------------------
# Hash-based message authentication codes
# -----------------------------------------------------------------------------------

def hmac_hash(algo, message: bytes, key: bytes) -> bytes:
    h = hmac.HMAC(key, algo, backend=default_backend())
    h.update(message)
    return h.finalize()

def hmac_verify(algo, message: bytes, key: bytes, signature: bytes) -> bool:
    h = hmac.HMAC(key, algo, backend=default_backend())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except exceptions.InvalidSignature:
        return False

def hmac_sha1_hash(message: bytes, key: bytes) -> bytes:
    return hmac_hash(hashes.SHA1(), message, key)
def hmac_sha1_verify(message: bytes, key: bytes, signature: bytes) -> bool:
    return hmac_verify(hashes.SHA1(), message, key, signature)
def hmac_sha256_hash(message: bytes, key: bytes) -> bytes:
    return hmac_hash(hashes.SHA256(), message, key)
def hmac_sha256_verify(message: bytes, key: bytes, signature: bytes) -> bool:
    return hmac_verify(hashes.SHA256(), message, key, signature)

