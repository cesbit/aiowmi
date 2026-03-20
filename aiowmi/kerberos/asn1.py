import struct
from typing import Union, Tuple


def asn1_tag(tag_num: int, content: bytes) -> bytes:
    """ASN.1 DER tagger."""
    length = len(content)
    if length < 128:
        len_octet = struct.pack('B', length)
    else:
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        len_octet = struct.pack('B', 0x80 + len(len_bytes)) + len_bytes
    return struct.pack('B', 0xa0 | tag_num) + len_octet + content


def asn1_len(n_or_b: Union[bytes, int]) -> bytes:
    n = n_or_b if isinstance(n_or_b, int) else len(n_or_b)
    if n <= 127:
        return struct.pack('B', n)
    l_bytes = []
    while n > 0:
        l_bytes.insert(0, n & 0xFF)
        n >>= 8
    return struct.pack('B', 0x80 | len(l_bytes)) + bytes(l_bytes)


def asn1_seq(content: bytes) -> bytes:
    return b'\x30' + asn1_len(content) + content


def asn1_gs(val: bytes) -> bytes:
    return b'\x1b' + asn1_len(val) + val


def asn1_int(val: int) -> bytes:
    num_bytes = (val.bit_length() + 8) // 8
    int_bytes = val.to_bytes(num_bytes, 'big', signed=True)
    return b'\x02' + asn1_len(int_bytes) + int_bytes


def asn1_gt(val: bytes) -> bytes:
    return b'\x18' + asn1_len(val) + val


def asn1_ostr(val: bytes) -> bytes:
    return b'\x04' + asn1_len(val) + val


def get_asn1_len(data: bytes, pos: int) -> Tuple[int, int]:
    """Read ASN.1 lengte from data."""
    b = data[pos]
    if b < 128:
        return b, 1
    num_bytes = b & 0x7f
    return int.from_bytes(data[pos+1: pos+1+num_bytes], 'big'), num_bytes + 1
