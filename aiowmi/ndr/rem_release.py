"""
ORPCTHIS

version
\x05\x00\x07\x00
flags
\x00\x00\x00\x00
reserverd
\x00\x00\x00\x00
cid
\xab\xbeX5\x81:\x82q\x80\xed\x8dq\x05\x84\xa8U
extensions
\x00\x00\x00\x00

cPublicInterfaces
\x01\x00

padding
\xce\xce

cPublicRefs ( <l )
\x01\x00\x00\x00

ipid
\x05p\x00\x00\xb8\x0b\x00\x00E\x1f\xaa\xa1\x8b\x16:\xc3

cMaxCount ( <L )
\x01\x00\x00\x00

cPrivateRefs ( <l )
\x00\x00\x00\x00


"""

import struct
from .activation_blob import ActivationBlob
from .activation_context_info_data import ActivationContextInfoData
from .instantiation_info_data import InstantiationInfoData
from .location_info_data import LocationInfoData
from .activation_context_info_data import ActivationContextInfoData
from .scm_request_info_data import ScmRequestInfoData
from .orpcthis import ORPCTHIS
from ..tools import gen_referent_id
from .objref_custom import ObjRefCustom


class RemRelease:

    FMT = '<Ll'

    def __init__(self, ipid: bytes):
        self.ipid = ipid

    def get_data(self) -> bytes:
        # 1 (<H c_interfaces) + padding + 1 (<l c_public_refs)
        fixed = '\x01\x00\xce\xce\x01\x00\x00\x00'
        c_max_count = 1
        c_private_refs = 0

        data = ORPCTHIS.get_data(flags=0) + fixed + self.ipid + struct.pack(
            self.FMT,
            c_max_count,
            c_private_refs,
        )

        return data
