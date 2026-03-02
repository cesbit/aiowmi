import struct


def asn1_tag(tag_num: int, content: bytes) -> bytes:
    """ASN.1 DER tagger."""
    length = len(content)
    if length < 128:
        len_octet = struct.pack('B', length)
    else:
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        len_octet = struct.pack('B', 0x80 + len(len_bytes)) + len_bytes
    return struct.pack('B', 0xa0 | tag_num) + len_octet + content


def asn1_len(n: int) -> bytes:
    if n <= 127:
        return struct.pack('B', n)
    l_bytes = []
    while n > 0:
        l_bytes.insert(0, n & 0xFF)
        n >>= 8
    return struct.pack('B', 0x80 | len(l_bytes)) + bytes(l_bytes)


def asn1_seq(content: bytes) -> bytes:
    return b'\x30' + asn1_len(len(content)) + content
