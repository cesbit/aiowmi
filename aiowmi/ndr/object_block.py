import struct
from typing import Tuple, Optional
from .encoded_string import EncodedString
from .class_part import ClassPart
from .heap import Heap
from .qualifier_set import QualifierSet


class ObjectBlock:

    FMT = '<L'
    FMT_SZ = struct.calcsize(FMT)

    INSTANCE = '<LBL'
    INSTANCE_SZ = struct.calcsize(INSTANCE)

    @classmethod
    def from_data(
            cls,
            data: bytes,
            offset: int,
            class_part: Optional[ClassPart] = None
            ) -> Tuple['ObjectBlock', int]:
        self = cls()

        # Start Object Block
        self.flags = data[offset]
        offset += 1

        if self.flags & 0x4:
            # WMIO - 2.2.6 - 0x4 If this flag is set,
            # the object has a Decoration block.
            self.dec_server_name, offset = \
                EncodedString.from_data(data, offset)

            self.dec_namespace_name, offset = \
                EncodedString.from_data(data, offset)

        if self.flags & 0x1:
            # The object is a CIM class.
            pass
            assert 0

        else:
            if self.flags & 0x10:
                # If this flag is set, the object is a prototype of the result
                # object for the query,
                # as specified in [MS-WMI] (section 2.2.4.1).
                # This flag MUST be used only in combination with the 0x1 flag.
                # This flag MUST NOT be used when returning IWbemClassObject,
                # which is not represented as a Prototype Result Object
                pass

            # Instance Type
            offset = self._instance_type(data, offset, class_part)

        return self, offset

    def _instance_type(
            self,
            data: bytes,
            offset: int,
            class_part: Optional[ClassPart] = None):
        if class_part:
            self.class_part = class_part
        else:
            self.class_part, offset = ClassPart.from_data(data, offset)

        # Instance
        (
            encoding_length,
            instance_flags,
            instance_class_name_n,
        ) = struct.unpack_from(self.INSTANCE, data, offset=offset)
        offset += self.INSTANCE_SZ

        # NdValueTable
        start = offset
        offset += self.class_part.nd_value_table_length
        self.nd_value_table = data[start: offset]

        # InstanceQualifierSet
        self.instance_qualifier_set, offset = \
            QualifierSet.from_data(data, offset)

        # InstPropQualSet
        flags = data[offset]
        offset += 1
        if flags & 0x2:
            assert 0, 'not supported yet'
        else:
            pass

        # InstanceHeap
        self.instance_heap, offset = Heap.from_data(data, offset)

        self.instance_qualifier_set.load(self.instance_heap)

        return offset
