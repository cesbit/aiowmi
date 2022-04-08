"""OBJREF_CUSTUM

See: 2.2.18.6, OBJREF_CUSTOM
"""
import struct
from ..dcom_const import CLSID_ActivationPropertiesIn
from ..dcom_const import IID_IActivationPropertiesIn
from ..dcom_const import FLAGS_OBJREF_CUSTOM
from ..uuid import uuid_part, bin_to_str, CLSID_SZ
from .objref import ObjRef


class ObjRefCustom(ObjRef):

    CUSTOM_FMT = '<LL'
    CUSTOM_FMT_SZ = struct.calcsize(CUSTOM_FMT)

    @classmethod
    def init(cls):
        objref = cls()

        objref.signature = 0x574F454D  # <L (1464812877)
        objref.flags = FLAGS_OBJREF_CUSTOM  # <L
        objref.iid = uuid_part(IID_IActivationPropertiesIn)  # 16b
        objref.clsid = CLSID_ActivationPropertiesIn  # 16b
        objref.cb_extension = 0  # <L
        objref.object_reference_size = None  # <L  (376)
        objref.object_data = None

        return objref

    @classmethod
    def from_data(cls, data: bytes, offset: int, size: int) -> 'ObjRefCustom':
        end = offset+size
        self = cls()

        self.read_objref(data, offset)
        offset += cls.OBJREF_SZ

        self.clsid = bin_to_str(data, offset=offset)
        offset += CLSID_SZ  # clsid size

        (
            self.cb_extension,
            self.object_reference_size
        ) = struct.unpack_from(cls.CUSTOM_FMT, data, offset=offset)
        offset += cls.CUSTOM_FMT_SZ

        self.object_data = data[offset:end]
        return self

    def set_object(self, blob: bytes):
        self.object_data = blob
        self.object_reference_size = len(blob) + 8

    def get_data(self) -> bytes:
        return super().get_data() + struct.pack(
            self.CUSTOM_FMT,
            self.cb_extension,
            self.object_reference_size
        ) + self.object_data
