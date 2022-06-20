import struct
from collections import OrderedDict
from typing import Tuple
from ..cim_type import CimType
from ..const import DICTIONARY_REFERENCE
from .encoded_string import EncodedString
from .property_info import PropertyInfo


class Properties:

    PROPERTY_LOOKUP_TABLE = '<L'
    PROPERTY_LOOKUP_TABLE_SZ = struct.calcsize(PROPERTY_LOOKUP_TABLE)

    PROPERTY = '<LL'
    PROPERTY_SZ = struct.calcsize(PROPERTY)

    nd_table_size: int
    props: list
    properties: OrderedDict

    @classmethod
    def from_data(cls, data: bytes, offset: int) -> Tuple['Properties', int]:
        self = cls()

        self.props = []
        self._qualifiers_done = False

        (
            property_count,
        ) = struct.unpack_from(cls.PROPERTY_LOOKUP_TABLE, data, offset=offset)
        offset += cls.PROPERTY_LOOKUP_TABLE_SZ

        for _ in range(property_count):
            # (property_name_ref, property_info_ref)
            prop = struct.unpack_from(cls.PROPERTY, data, offset=offset)
            offset += cls.PROPERTY_SZ
            self.props.append(prop)

        self.nd_table_size = (property_count - 1) // 4 + 1

        return self, offset

    def copy(self):
        cp = Properties()
        cp.props = self.props
        cp.nd_table_size = self.nd_table_size
        cp.properties = self.properties.copy()
        return cp

    def load(self, heap: bytes, nd_value_table: bytes):
        properties = []
        for (name_ref, info_ref) in self.props:
            if name_ref & 0x80000000:
                name = DICTIONARY_REFERENCE[name_ref & 0x7fffffff]
            else:
                name, _ = EncodedString.from_data(heap, name_ref)

            prop = PropertyInfo(heap, info_ref)

            properties.append((name, prop))

        self.properties = \
            OrderedDict(sorted(properties, key=lambda x: x[1].order))

    def set_prop_values(
            self,
            heap: bytes,
            nd_value_table: bytes,
            set_defaults: bool = False,
            ignore_missing: bool = False,
            ignore_defaults: bool = False):

        assert not set_defaults or not ignore_missing, \
            'set_default and ignore_missing cannot both be True'

        offset = self.nd_table_size

        for name, prop in tuple(self.properties.items()):
            # Let's get the default Values
            if prop.type & CimType.CIM_ARRAY_FLAG:
                fmt, size = '<L', 4
            else:
                fmt, size = CimType.get_cim_type_ref(prop.type)

            item_value, = \
                struct.unpack_from(fmt, nd_value_table, offset=offset)
            offset += size

            if item_value == 0xffffffff or \
                    item_value == 0x0 or \
                    (set_defaults and not prop.inherited_default):

                if ignore_missing:
                    del self.properties[name]
                    continue
                if set_defaults:
                    prop._set_type_default()
                elif ignore_defaults:
                    prop.value = None
                continue

            # TODO: what to do with prop.null_default ?
            prop._set_value(item_value, heap)

    def set_prop_defaults(self, nd_value_table: bytes):
        """NdTable

        see [MS-WMIO]: 2.2.26 NdTable and 2.2.27 NullAndDefaultFlag
        """
        nd_table = nd_value_table[:self.nd_table_size]

        nd_table = [
            (b >> shift) & 0b11
            for b in nd_table for shift in (0, 2, 4, 6)]

        for prop in self.properties.values():
            nd_entry = nd_table[prop.order]
            prop.null_default = bool(nd_entry & 1)
            prop.inherited_default = bool(nd_entry & 2)

    def set_qualifiers(self, heap: bytes):
        if self._qualifiers_done:
            return
        self._qualifiers_done = True
        for prop in self.properties.values():
            prop._set_qualifiers(heap)
