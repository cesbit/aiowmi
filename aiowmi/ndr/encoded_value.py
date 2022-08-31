import struct
from ..cim_type import CimType
from .encoded_string import EncodedString
from ..dtypes.dt import dt_from_str


class EncodedValue:

    FMT = '<L'
    FMT_SZ = struct.calcsize(FMT)

    @classmethod
    def _get_array(cls, p_type: int, cim_type: int, entry: int, heap: bytes):

        num_items, = struct.unpack_from(cls.FMT, heap, offset=entry)
        num_items &= ~CimType.CIM_ARRAY_FLAG

        offset = entry + cls.FMT_SZ

        arr = []
        fmt, size = CimType.CIM_TYPES_REF[p_type]

        if cim_type == CimType.CIM_ARRAY_STRING:
            # We have an array of strings
            # First items are DWORDs with the string pointers
            # inside the heap. We don't need those ones
            offset += size * num_items
            # Let's now grab the strings
            for _ in range(num_items):
                item, offset = EncodedString.from_data(heap, offset)
                arr.append(item)
        elif cim_type == CimType.CIM_ARRAY_OBJECT:
            # Discard the pointers
            offset += size * num_items
            for item in range(num_items):
                assert 0

                (
                    encoding_len,
                ) = struct.unpack_from(cls.FMT, heap, offset=offset)
                offset += cls.FMT_SZ

                item, offset = ObjectBlock.from_data(heap, offset)
                # TODO: test parsing
                # msb = METHOD_SIGNATURE_BLOCK(heapData)
                # unit = ENCODING_UNIT()
                # unit['ObjectEncodingLength'] = msb['EncodingLength']
                # unit['ObjectBlock'] = msb['ObjectBlock']
                # array.append(unit)
                # heapData = heapData[msb['EncodingLength']+4:]
        else:
            for item in range(num_items):
                item, = struct.unpack_from(fmt, heap, offset=offset)
                arr.append(item)
                offset += size
        return arr

    @classmethod
    def get_value(cls, cim_type: int, entry: int, heap: bytes):
        from .object_block import ObjectBlock
        p_type = \
            cim_type & (~(CimType.CIM_ARRAY_FLAG | CimType.CIM_INHERITED_FLAG))

        if entry == 0xffffffff:
            return  # None

        if cim_type & CimType.CIM_ARRAY_FLAG:
            return cls._get_array(p_type, cim_type, entry, heap)

        if p_type == CimType.CIM_TYPE_BOOLEAN:
            return entry == 0xffff

        if p_type == CimType.CIM_TYPE_OBJECT:
            # If the value type is CIM-TYPE-OBJECT, the EncodedValue is a
            # HeapRef to the object encoded as an
            # ObjectEncodingLength (section 2.2.4) followed by an
            # ObjectBlock (section 2.2.5).

            # msb = METHOD_SIGNATURE_BLOCK(heapData)
            # unit = ENCODING_UNIT()
            # unit['ObjectEncodingLength'] = msb['EncodingLength']
            # unit['ObjectBlock'] = msb['ObjectBlock']
            # value = unit
            assert 0

        if p_type not in (
                CimType.CIM_TYPE_STRING,
                CimType.CIM_TYPE_DATETIME,
                CimType.CIM_TYPE_REFERENCE):
            return entry

        try:
            value, _ = EncodedString.from_data(heap, entry)
        except UnicodeDecodeError:
            raise  # TODO: dump heap data for debugging?

        if p_type == CimType.CIM_TYPE_DATETIME:
            return dt_from_str(value)  # Returns type datetime or timedelta

        return value
