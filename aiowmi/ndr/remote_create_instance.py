import struct
from ..tools import gen_referent_id
from .activation_blob import ActivationBlob
from .activation_context_info_data import ActivationContextInfoData
from .activation_context_info_data import ActivationContextInfoData
from .instantiation_info_data import InstantiationInfoData
from .location_info_data import LocationInfoData
from .objref_custom import ObjRefCustom
from .orpcthis import ORPCTHIS
from .scm_request_info_data import ScmRequestInfoData


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
