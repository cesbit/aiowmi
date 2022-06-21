import hashlib
import hmac
import random
import string
import socket
import struct
import datetime
from Crypto.Cipher import DES, ARC4
from Crypto.Hash import MD4
from typing import Tuple


KNOWN_DES_INPUT = b"THIS!MTB"


def pad4(size) -> int:
    return (4 - size % 4) % 4


def pad8(size) -> int:
    return (8 - size % 8) % 8


def pad(size, is_ndr64=False) -> int:
    return pad8(size) if is_ndr64 else pad4(size)


def gen_referent_id() -> int:
    return random.randint(1, 65535)


def gen_cid() -> bytes:
    top = (1 << 31)-1
    return struct.pack(
        "IIII",
        random.randrange(top),
        random.randrange(top),
        random.randrange(top),
        random.randrange(top))


def _des_expand_key(key, offset: int) -> bytes:
    # Expand the key from a 7-byte password key into a 8-byte DES key
    key = bytearray(key[offset:offset+7]).ljust(7, b'\x00')
    return bytes(bytearray((
        (((key[0] >> 1) & 0x7f) << 1)
        (((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1)
        (((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1)
        (((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1)
        (((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1)
        (((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1)
        (((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1)
        ((key[6] & 0x7f) << 1))))


def compute_lmhash(password: str):
    # This is done according to Samba's encryption
    # specification (docs/html/ENCRYPTION.html)
    password = password.upper().encode("latin-1")
    key = _des_expand_key(password, 0)
    lmhash = DES.new(key, DES.MODE_ECB).encrypt(KNOWN_DES_INPUT)
    key = _des_expand_key(password, 7)
    return lmhash + DES.new(key, DES.MODE_ECB).encrypt(KNOWN_DES_INPUT)


def compute_nthash(password: str):
    # This is done according to Samba's encryption
    # specification (docs/html/ENCRYPTION.html)
    hash = MD4.new()
    hash.update(password.encode('utf_16le'))
    return hash.digest()


def hmac_md5(key, data):
    hash = hmac.new(key, digestmod=hashlib.md5)
    hash.update(data)
    return hash.digest()


def ntowf_v2(user: str, password: str, domain: bytes):
    hash = hmac.new(compute_nthash(password), digestmod=hashlib.md5)
    hash.update(user.upper().encode('utf-16le') + domain)
    return hash.digest()


def get_rangom_bytes(length):
    return bytes(''.join(
        random.choice(string.digits+string.ascii_letters)
        for _ in range(length)), 'latin-1')


def hmac_md5(key: bytes, data: bytes):
    h = hmac.new(key, digestmod=hashlib.md5)
    h.update(data)
    return h.digest()


def encrypted_session_key(key_exchange_key, exported_session_key):
    return ARC4.new(key_exchange_key).encrypt(exported_session_key)


def read_string_bindings(data: bytes, offset: int) -> Tuple[list, int]:
    bindings = []

    while True:
        w_tower_id, = struct.unpack_from('<H', data, offset=offset)
        offset += 2  # size (<H)
        if w_tower_id == 0:
            break
        end = data.find(b'\x00\x00', offset)
        end += (end - offset) % 2 + 2
        raw = data[offset: end]
        bindings.append((w_tower_id, raw.decode('utf-16le')))
        offset = end

    return bindings, offset


def get_null(is_ndr64=False):
    return b'\x00\x00\x00\x00\x00\x00\x00\x00' \
        if is_ndr64 else b'\x00\x00\x00\x00'


def is_fqdn(target):
    try:
        socket.inet_aton(target)
    except Exception:
        try:
            target.index(':')
        except Exception:
            return True
    return False


def dt_fmt(dt: datetime.datetime) -> str:
    """Returns type datetime as a string according the Microsoft
    WMI Query Language (WQL) queries format.
    https://docs.microsoft.com/en-us/windows/win32/wmisdk/cim-datetime
    """
    minutes = dt.utcoffset().total_seconds() // 60
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')}{minutes:+04g}"
