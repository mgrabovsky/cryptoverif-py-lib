import crypto
import io, math, os, random, struct, sys
import functools
import socket
from cryptography.hazmat.primitives.asymmetric import rsa

class BadCall(Exception):
    pass

class MatchFail(Exception):
    pass

class Abort(Exception):
    pass

class BadFile(Exception):
    pass

# -----------------------------------------------------------------------------------
# Type predicates
# -----------------------------------------------------------------------------------

def true_pred(x) -> bool:
    """
    A predicate that is always L{True}.
    """
    return True

def size_pred(n) -> bool:
    """
    Generate a function that returns L{True} iff its arguments length L{n}.
    """
    return lambda s: len(s) == n

# -----------------------------------------------------------------------------------
# Random data generation
# -----------------------------------------------------------------------------------

def random_bytes(n: int) -> bytes:
    """
    Generate a random bytestring of length L{n}.
    """
    rand = os.urandom(n)
    assert len(rand) == n
    return rand

def random_nat(n: int) -> int:
    """
    Generate a random natural number L{n} bytes long.
    """
    return int.from_bytes(random_bytes(n), 'big', signed=False)

def random_bool() -> bool:
    """
    Generate a random Boolean value.
    """
    s = random_bytes(1)[0]
    return s % 2 == 0

def random_list(xs):
    """
    Return a random elements of a list.
    """
    return random.choice(xs)

# -----------------------------------------------------------------------------------
# File input and output
# -----------------------------------------------------------------------------------

def read_file(fname) -> bytes:
    """
    Read the contents of a file as a byte string.
    """
    buf = None
    with open(fname, 'rb') as f:
        buf = f.read()
    return buf

def write_file(fname, data: bytes) -> None:
    """
    Write byte string to a file.
    """
    with open(fname, 'wb') as f:
        f.write(data)

# -----------------------------------------------------------------------------------
# Serialization
# -----------------------------------------------------------------------------------

# TODO: Name is too specific
def prefix_size(data: bytes, size: int) -> bytes:
    """
    Prefix a byte string with 4-byte size field.
    """
    prefix = struct.pack('!L', size)
    return prefix + data

def extract_size(data: bytes):
    """
    Extract the size field from given byte string.
    """
    if len(data) < 4:
        raise BadCall()

    (size,) = struct.unpack('!L', data[:4])
    return (data[4:], size)

def compose(xs: bytes) -> bytes:
    """
    Serialize a list of byte string into a single byte string with size annotation.
    """
    buf = prefix_size(b'', len(xs))

    for x in xs:
        buf += prefix_size(x, len(x))

    return buf

def decompose(data_with_size: bytes) -> list:
    """
    Deserialize a byte string into a list of byte strings.
    """
    (buf, size) = extract_size(data_with_size)
    if size < 0:
        raise BadFile()

    xs = []
    for i in range(size):
        (buf2, chunk_size) = extract_size(buf)
        chunk = buf2[:chunk_size]
        xs.append(chunk)
        buf = buf2[chunk_size:]

    return xs

def concat(*xs: bytes) -> bytes:
    return compose(xs)

def concat_pubkey_str(pk: rsa.RSAPublicKey, bs: bytes) -> bytes:
    return compose([crypto.serialize_pubkey(pk), bs])

def unconcat_pubkey_str(bs: bytes):
    xs = decompose(bs)
    if len(xs) != 2:
        raise Exception('Invalid string')
    return [load_pubkey(xs[0]), xs[1]]

# -----------------------------------------------------------------------------------
# Encoding tables
# -----------------------------------------------------------------------------------

def get_from_table(fname):
    """
    Retrieve all records from a table file.
    """
    data = []

    with open(fname, 'rb') as f:
        while True:
            # Read the number of records in this table
            word = f.read(4)
            if word is None or len(word) < 4:
                # Fail silently on EOF to support insertion while reading
                break
            (ncomp,) = struct.unpack('!L', word)

            records = []
            for _ in range(ncomp):
                word = f.read(4)
                if word is None or len(word) < 4:
                    # Fail silently
                    break
                (length,) = struct.unpack('!L', word)
                records.append(f.read(length))

            try:
                data.insert(0, records)
            except MatchFail:
                continue

    return data

def insert_into_table(fname, data: bytes) -> None:
    """
    Insert a new record into a table file.
    """
    length = len(data)

    with open(fname, 'ab') as f:
        f.write(struct.pack('!L', length))
        for x in data:
            f.write(struct.pack('!L', len(x)) + x)

# -----------------------------------------------------------------------------------
# Auxiliary functions
# -----------------------------------------------------------------------------------

def load_bool(bs: bytes) -> bool:
    if bs == b'\x01':
        True
    elif bs == b'\x00':
        False
    else:
        raise BadCall()

def serialize_bool(b: bool) -> bytes:
    if b:
        return b'\x01'
    else:
        return b'\x00'

def size_from(n: int):
    pred = size_pred(n)
    def inner(s):
        if not pred(s):
            raise BadCall()
        return s
    return inner

def load_stringbot(bs: bytes) -> bytes:
    if bs == b'':
        raise BadCall()
    elif bs[0] == b'N':
        return None
    elif bs[1] == b'S':
        return bs[1:]
    else:
        raise BadCall()

def serialize_stringbot(bs: bytes) -> bytes:
    if bs is None:
        return b'N'
    else:
        return b'S' + bs

def injbot_inv(x):
    if x is None:
        raise BadCall()
    return x

def get_hostname() -> bytes:
    return bytes(socket.gethostname(), encoding='utf-8')

