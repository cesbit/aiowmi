import struct
from typing import Tuple
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
    def from_data(cls, data: bytes, offset: int) -> Tuple['ObjectBlock', int]:
        self = cls()
        (
            encoding_len,
        ) = struct.unpack_from(cls.FMT, data, offset=offset)
        offset += cls.FMT_SZ

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
            # Instance Type
            self._instance_type(data, offset)

        return self, offset

    def _instance_type(self, data, offset):
        # ClassPart
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
