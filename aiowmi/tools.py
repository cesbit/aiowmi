import os
import hashlib
import hmac
import random
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


def compute_nthash(password: str):
    # This is done according to Samba's encryption
    # specification (docs/html/ENCRYPTION.html)
    hash = MD4.new()
    hash.update(password.encode('utf_16le'))
    return hash.digest()


def ntowf_v2(user: str, password: str, domain: bytes):
    hash = hmac.new(compute_nthash(password), digestmod=hashlib.md5)
    hash.update(user.upper().encode('utf-16le') + domain)
    return hash.digest()


def get_random_bytes(length: int) -> bytes:
    return os.urandom(length)


def hmac_md5(key: bytes, data: bytes):
    h = hmac.new(key, digestmod=hashlib.md5)
    h.update(data)
    return h.digest()


def encrypted_session_key(key_exchange_key, exported_session_key):
    return ARC4.new(key_exchange_key).encrypt(exported_session_key)


def read_string_bindings(data: bytes, offset: int) -> Tuple[list, int]:
    bindings = []
    data_len = len(data)

    while offset + 2 <= data_len:
        w_tower_id, = struct.unpack_from('<H', data, offset=offset)
        offset += 2

        if w_tower_id == 0:
            return bindings, offset

        current_pos = offset
        found = False
        end = 0
        while current_pos + 1 < data_len:
            if data[current_pos:current_pos+2] == b'\x00\x00':
                end = current_pos + 2
                found = True
                break
            current_pos += 2

        if not found:
            raise ValueError(
                'Malformed NDR: String binding terminator not found')

        raw = data[offset:end]
        try:
            decoded = raw.decode('utf-16le').rstrip('\x00')
            bindings.append((w_tower_id, decoded))
        except UnicodeDecodeError:
            raise ValueError(
                'Malformed NDR: Invalid UTF-16 encoding in string binding')

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
    offset = dt.utcoffset()
    if offset is not None:
        minutes = offset.total_seconds() // 60
    else:
        minutes = 0
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')}{minutes:+04g}"
