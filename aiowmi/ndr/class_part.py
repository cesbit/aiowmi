import struct
from .heap import Heap
from .encoded_string import EncodedString
from .qualifier_set import QualifierSet
from .properties import Properties


class ClassPart:

    HEADER = '<LBLL'
    HEADER_SZ = struct.calcsize(HEADER)

    DIRIVATION_LIST = '<L'
    DIRIVATION_LIST_SZ = struct.calcsize(DIRIVATION_LIST)

    properties: Properties

    @classmethod
    def from_data(cls, data, offset):
        keep = offset

        # ClassHeader
        self = cls()
        (
            encoding_length,
            reserved,
            self.class_name_ref,
            self.nd_value_table_length,
        ) = struct.unpack_from(cls.HEADER, data, offset=offset)
        offset += cls.HEADER_SZ

        # DerivationList
        (
            enc_length,
        ) = struct.unpack_from(cls.DIRIVATION_LIST, data, offset=offset)
        end = offset + enc_length
        start = offset + cls.DIRIVATION_LIST_SZ

        self.class_name_encoding = data[start: end]
        offset += enc_length

        # QualifierSet
        self.qualifier_set, offset = QualifierSet.from_data(data, offset)

        # Properties
        self.properties, offset = Properties.from_data(data, offset)

        start = offset
        offset += self.nd_value_table_length
        self.nd_value_table = data[start: offset]

        # ClassHeap
        self.class_heap, offset = Heap.from_data(data, offset)

        garbage_size = encoding_length - (offset - keep)
        #  self.garbage = data[offset: offset+garbage_size]
        offset += garbage_size

        self.qualifier_set.load(self.class_heap)
        self.properties.load(self.class_heap, self.nd_value_table)

        return self, offset

    def get_name(self):
        if self.class_name_ref == 0xffffffff:
            return 'None'

        heap = self.class_heap
        name, offset = EncodedString.from_data(heap, self.class_name_ref)

        names = [name]
        dlist = self.class_name_encoding
        offset, end = 0, len(dlist)
        while offset < end:
            super_class, offset = EncodedString.from_data(dlist, offset)
            names.append(super_class)

        return ':'.join(names)
