import struct
from typing import Tuple
from .qualifier import Qualifier
from ..const import DICTIONARY_REFERENCE
from .encoded_string import EncodedString
from .encoded_value import EncodedValue


class QualifierSet:

    QUALIFIER_SET = '<L'
    QUALIFIER_SET_SZ = struct.calcsize(QUALIFIER_SET)

    @classmethod
    def from_data(cls, data: bytes, offset: int) -> Tuple['QualifierSet', int]:
        self = cls()
        (
            enc_length,
        ) = struct.unpack_from(cls.QUALIFIER_SET, data, offset=offset)
        end = offset + enc_length
        start = offset + cls.QUALIFIER_SET_SZ

        self.qualifier_set = data[start: end]
        offset += enc_length

        # call load() to get the qualifiers as soon as the heap is loaded
        self.qualifiers = dict()

        return self, offset

    def load(self, heap):
        data = self.qualifier_set
        offset, end = 0, len(data)

        while offset < end:
            qualifier, offset = Qualifier.from_data(data, offset)
            if qualifier.name == 0xffffffff:
                name = b''
            elif qualifier.name & 0x80000000:
                name = DICTIONARY_REFERENCE[qualifier.name & 0x7fffffff]
            else:
                name, _ = EncodedString.from_data(heap, qualifier.name)

            value = EncodedValue.get_value(
                qualifier.type,
                qualifier.value,
                heap)

            self.qualifiers[name] = value
