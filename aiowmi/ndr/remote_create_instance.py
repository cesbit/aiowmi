"""
ORPCTHIS

version
\x05\x00\x07\x00
flags
\x01\x00\x00\x00
reserverd
\x00\x00\x00\x00
cid
\xcf=\xd6\x19\xff\xf5\xfb\x11\xc5\xbc\x85[\xec*\xc9$
extensions (4 / 8)
\x00\x00\x00\x00

p_unk_outer
\x00\x00\x00\x00

referent_id (4) random
\xc2h\x00\x00

ulCntData (416)
\xa0\x01\x00\x00

again??? (4)
\xa0\x01\x00\x00

OBJ REF

signature (4)
MEOW

flags (4)
\x04\x00\x00\x00

OBJ REF CUSTOM

iid (16)
\xa2\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F

clsid (16)
8\x03\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F

extensions (4)
\x00\x00\x00\x00

object_ref_size (4) (376 = below + 8)
x\x01\x00\x00

ActivationBLOB

h\x01\x00\x00\x00...

padding
\xfa\xfa\xfa\xfa\xfa\xfa'
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


class RemoteCreateInstance:

    FMT32 = '<LLLL'
    FMT64 = '<QQLL'

    def __init__(self, class_id: bytes, iid: bytes):

        activatoin_blob = ActivationBlob()

        activatoin_blob.add_info_data(InstantiationInfoData(class_id, iid))
        activatoin_blob.add_info_data(LocationInfoData)
        activatoin_blob.add_info_data(ActivationContextInfoData)
        activatoin_blob.add_info_data(ScmRequestInfoData)

        obj_ref_custom = ObjRefCustom.init()
        obj_ref_custom.set_object(activatoin_blob.get_data())

        self.ab_data = obj_ref_custom.get_data()

    def get_data(self) -> bytes:

        p_unk_outer = 0
        referent_id = gen_referent_id()
        c_ab_data = len(self.ab_data)

        data = ORPCTHIS.get_data(flags=1) + struct.pack(
            self.FMT32,
            p_unk_outer,
            referent_id,
            c_ab_data,
            c_ab_data,
        ) + self.ab_data

        return data
