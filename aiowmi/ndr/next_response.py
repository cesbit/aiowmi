import struct
from typing import OrderedDict
from .orpcthat import ORPCTHAT
from .objref_standard import ObjRefStandard
from .activation_blob import ActivationBlob
from .scm_reply_info_data import ScmReplyInfoData
from .props_out_info import PropsOutInfo
from ..tools import is_fqdn
from .varying_array import VaryingArray
from .encoding_unit import EncodingUnit
from .property_info import PropertyInfo


class NextResponse:

    _FMT1_32 = '<LLL'
    _FMT1_64 = '<QQQ'

    _FMT1_32_SZ = struct.calcsize(_FMT1_32)
    _FMT1_64_SZ = struct.calcsize(_FMT1_64)

    def __init__(self, data: bytes):
        self.orpcthat, offset = ORPCTHAT.from_data(data, offset=0)
        (
            ncount,
            noffset,
            ncount,
        ) = struct.unpack_from(self._FMT1_32, data, offset)
        offset += self._FMT1_32_SZ
        self._ap_objects = []

        for _ in range(ncount):
            va, offset = VaryingArray.from_data(data, offset)
            encoding_unit = EncodingUnit(va.objref.object_data)
            self._ap_objects.append(encoding_unit)

        (
            self.pu_returned,
            self.error_code,
        ) = struct.unpack_from('<LL', data, offset)

    def get_properties(
            self,
            ignore_defaults: bool = False,
            ignore_missing: bool = False,
            load_qualifiers: bool = False) -> OrderedDict[str, PropertyInfo]:
        """Get properties
        ignore_defaults: Ignore default values. Set missing values to None
                         if a value does not exist in the current class.
                         ignore_defaults will always be True if ignore_missing
                         is set to True.
        ignore_missing: If set to True, values missing in the current class
                        will not be part of the result.
        load_qualifiers: Load the qualifiers of the properties. If not, the
                         property qualifier_set will have the offset in the
                        heap where the qualifiers are stored.
        """

        items = []
        assert len(self._ap_objects) == 1
        for encoding_unit in self._ap_objects:
            object_block = encoding_unit.object_block
            class_part = object_block.class_part
            properties = class_part.properties

            if not ignore_defaults:
                properties.set_prop_defaults(class_part.nd_value_table)
                properties.set_prop_values(
                    class_part.class_heap,
                    class_part.nd_value_table,
                    set_defaults=True)

            properties.set_prop_values(
                object_block.instance_heap,
                object_block.nd_value_table,
                ignore_missing=ignore_missing)

            if load_qualifiers:
                properties.set_qualifiers(class_part.class_heap)

            return properties.properties
