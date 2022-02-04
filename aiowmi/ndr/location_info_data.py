"""

\x01\x10\x08\x00\xcc\xcc\xcc\xcc
\x10\x00\x00\x00\xcc\xcc\xcc\xcc


\x00\x00\x00\x00
\x00\x00\x00\x00
\x00\x00\x00\x00
\x00\x00\x00\x00'

"""
import struct
from .common import NdrCommon
from ..dcom_const import CLSID_ServerLocationInfo


class LocationInfoData(NdrCommon):

    CLSID = CLSID_ServerLocationInfo

    BUFFER_FMT = "<LLLL"

    @classmethod
    def get_data(cls) -> bytes:

        machine_name = 0
        process_id = 0
        apartment_id = 0
        context_id = 0

        buffer = struct.pack(
            cls.BUFFER_FMT,
            machine_name,       # <l
            process_id,         # <l
            apartment_id,       # <L
            context_id,         # <L
        )

        private, padding = cls.get_private(buffer)

        return cls.get_common() + private + buffer + padding
