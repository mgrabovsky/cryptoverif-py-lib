import base
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa

# -----------------------------------------------------------------------------------
# Padding
# -----------------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------------
# Symmetric cryptography
# -----------------------------------------------------------------------------------
SYM_BLOCK_SIZE = 16

# Encryption & decryption
def sym_encrypt(message: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt a message using AES in counter (CTR) mode with given key and
    initialisation vector.

    Returns the ciphertext as a byte string.
    """
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv),
            backend=default_backend()).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    return ciphertext

def sym_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt a message encrypted under AES in CTR mode with given key and
    initialisation vector.

    Returns the message as a byte string.
    """
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CTR(iv),
                backend=default_backend()).decryptor()

        message = decryptor.update(ciphertext) + decryptor.finalize()

        return message
    except Exception:
        return None

# -----------------------------------------------------------------------------------
# Public-key cryptography
# -----------------------------------------------------------------------------------

# Key generation
def pk_keygen(size: int):
    """
    Generate an RSA key pair with modulo of given bitsize.
    """
    key = rsa.generate_private_key(65537, size, default_backend())
    return (key.public_key(), key)

# Key serialization
def load_pubkey(bs: bytes) -> rsa.RSAPublicKey:
    """
    Parse a DER-encoded RSA public key from a byte string.
    """
    key = serialization.load_der_public_key(bs, default_backend())
    if not isinstance(key, rsa.RSAPublicKey):
        raise Exception('Not an RSA public key')
    return key

def serialize_pubkey(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encode an RSA public key into the DER format.
    """
    return public_key.public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

def load_privkey(bs: bytes) -> rsa.RSAPrivateKey:
    """
    Parse a DER-encoded RSA private key from a byte string.
    """
    key = serialization.load_der_private_key(bs, None, default_backend())
    if not isinstance(key, rsa.RSAPrivateKey):
        raise Exception('Not an RSA private key')
    return key

def serialize_privkey(private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Serialize an RSA private into the DER format.
    """
    return private_key.private_bytes(serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

# Encryption & decryption -- RSA OAEP
def pk_encrypt(message: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt a message using RSAES-OAEP.
    """
    ciphertext = public_key.encrypt(message, padding.OAEP(
            padding.MGF1(hashes.SHA1()),
            hashes.SHA1(),
            None))
    return ciphertext

def pk_decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Decrypt an RSAES-OAEP-encrypted message.
    """
    plaintext = private_key.decrypt(ciphertext, padding.OAEP(
            padding.MGF1(hashes.SHA1()),
            hashes.SHA1(),
            None))
    return plaintext

# Digital signing -- RSA PSS
def pk_sign(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign a message using RSASSA-PSS.
    """
    signer = private_key.signer(padding.PSS(padding.MGF1(hashes.SHA256()),
            padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    signer.update(message)
    return signer.finalize()

def pk_verify(message: bytes, public_key: rsa.RSAPublicKey,
        signature: bytes) -> bool:
    """
    Verify a message signature created with RSASSA-PSS.
    """
    verifier = public_key.verifier(signature,
        padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH),
        hashes.SHA256())
    verifier.update(message)

    try:
        verifier.verify()
        return True
    except exceptions.InvalidSignature:
        return False

# -----------------------------------------------------------------------------------
# Hash-based message authentication codes
# -----------------------------------------------------------------------------------

# Generic wrapper
def hmac_hash(algo: hashes.HashAlgorithm, message: bytes, key: bytes) -> bytes:
    h = hmac.HMAC(key, algo, backend=default_backend())
    h.update(message)
    return h.finalize()

def hmac_verify(algo: hashes.HashAlgorithm, message: bytes, key: bytes,
        signature: bytes) -> bool:
    h = hmac.HMAC(key, algo, backend=default_backend())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except exceptions.InvalidSignature:
        return False

# Specialized functions
def hmac_sha1_hash(message: bytes, key: bytes) -> bytes:
    return hmac_hash(hashes.SHA1(), message, key)
def hmac_sha1_verify(message: bytes, key: bytes, signature: bytes) -> bool:
    return hmac_verify(hashes.SHA1(), message, key, signature)
def hmac_sha256_hash(message: bytes, key: bytes) -> bytes:
    return hmac_hash(hashes.SHA256(), message, key)
def hmac_sha256_verify(message: bytes, key: bytes, signature: bytes) -> bool:
    return hmac_verify(hashes.SHA256(), message, key, signature)

# -----------------------------------------------------------------------------------
# Diffie-Hellman-Merkle key exchange
# -----------------------------------------------------------------------------------

# https://tools.ietf.org/html/rfc3526#section-2
dh_group5 = cryptography.hazmat.primitives.asymmetric.dh.DHParameterNumbers(
    p=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff,
    g=2)

# https://tools.ietf.org/html/rfc3526#section-3
dh_group14 = cryptography.hazmat.primitives.asymmetric.dh.DHParameterNumbers(
    p=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff,
    g=2)

# https://tools.ietf.org/html/rfc3526#section-4
dh_group15 = cryptography.hazmat.primitives.asymmetric.dh.DHParameterNumbers(
    p=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff,
    g=2)

