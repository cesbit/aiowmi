import struct
from .orpcthat import ORPCTHAT
from .objref_standard import ObjRefStandard
from .activation_blob import ActivationBlob
from .scm_reply_info_data import ScmReplyInfoData
from .props_out_info import PropsOutInfo
from ..tools import is_fqdn
from .interface import NdrInterface

"""
IWbemLevel1Login_NTLMLoginResponse

ORPCTHAT
flags
\x00\x00\x00\x00
ext
\x00\x00\x00\x00


\x00\x00\x02\x00\xb4\x00\x00\x00\xb4\x00\x00\x00MEOW\x01\x00\x00\x00...
"""


class NTLMLoginResponse(NdrInterface):

    FMT1_32 = '<LLL'
    FMT1_64 = '<QLL'

    FMT1_32_SZ = struct.calcsize(FMT1_32)

    def __init__(self, data: bytes):
        self.orpcthat, offset = ORPCTHAT.from_data(data, offset=0)

        # activation_blobs

        (
            self.referent_id,
            _,
            size
        ) = struct.unpack_from(self.FMT1_32, data, offset)
        offset += self.FMT1_32_SZ

        self.objref = ObjRefStandard.from_data(data, offset, size)
        offset += size

        self.error_code, = struct.unpack_from('<L', data, offset)
        assert self.error_code == 0, f'error code: {self.error_code}'

    def get_ipid(self):
        return self.objref.ipid
