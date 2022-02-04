import struct
import binascii
from typing import Callable
from .const import (
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
)
from ..tools import hmac_md5


class NTLMMessageSignature:

    @staticmethod
    def get_data(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,
            signing_key: bytes,
            handle: Callable[[bytes, bytes], bytes]):

        version = 1

        if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:

            checksum = hmac_md5(
                signing_key,
                struct.pack('<i', seq_num) + message_to_sign)[:8]

            if flags & NTLMSSP_NEGOTIATE_KEY_EXCH:
                checksum = handle(checksum)

            checksum, = struct.unpack('<q', checksum)

            signature = struct.pack(
                '<LqI',
                version,
                checksum,
                seq_num)
            return signature

        checksum = \
            struct.pack('<I', binascii.crc32(message_to_sign) & 0xFFFFFFFF)
        checksum, = struct.unpack('<I', handle(checksum))
        seq_num = struct.unpack('<I', handle(b'\x00\x00\x00\x00'))[0] ^ seq_num
        random_pad = 0

        signature = struct.pack(
                '<LIII',
                version,
                random_pad,
                checksum,
                seq_num)
        return signature
