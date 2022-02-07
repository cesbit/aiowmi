import re
import binascii
import struct
from typing import Tuple


CLSID_SZ = 16


def uuid_to_bin(uuid: str) -> bytes:
    """UUID to bin
    UUID format: 00000000-0000-0000-0000-000000000000
    The first three components of the UUID are little-endian,
    and the last two are big-endian
    """

    matches = re.match(
        r"([\dA-Fa-f]{8})-"
        r"([\dA-Fa-f]{4})-"
        r"([\dA-Fa-f]{4})-"
        r"([\dA-Fa-f]{4})-"
        r"([\dA-Fa-f]{4})"
        r"([\dA-Fa-f]{8})", uuid)

    uuid1, uuid2, uuid3, uuid4, uuid5, uuid6 = [
        int(x, 16) for x in matches.groups()]

    # Little endian
    uuid = struct.pack('<LHH', uuid1, uuid2, uuid3)

    # Big endian
    uuid += struct.pack('>HHL', uuid4, uuid5, uuid6)

    return uuid


def ver_to_bin(ver: str) -> bytes:
    """Version to bin
    Version format: 0.0
    Both Little Endian
    """
    return struct.pack('<HH', *(int(x) for x in ver.split('.')))


def uuid_ver_to_bin(uuid, ver) -> bytes:
    return uuid_to_bin(uuid) + ver_to_bin(ver)


def uuid_part(uuid_ver: bytes) -> bytes:
    return uuid_ver[:-4]


def bin_to_str(bin: bytes, offset: int) -> str:
    uuid1, uuid2, uuid3 = struct.unpack_from('<LHH', bin, offset)
    uuid4, uuid5, uuid6 = struct.unpack_from('>HHL', bin, offset+8)
    return '%08X-%04X-%04X-%04X-%04X%08X' % (
        uuid1, uuid2, uuid3, uuid4, uuid5, uuid6)


def bin_to_uuid_ver(bin, offset) -> Tuple[str, str]:
    uuidstr = bin_to_str(bin, offset)
    ma, mi = struct.unpack_from("<HH", bin, offset+16)
    return uuidstr, f'{ma}.{mi}'
