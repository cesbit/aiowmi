import struct
from datetime import datetime, timedelta
from typing import Tuple, Union


class CimType:
    CIM_ARRAY_FLAG = 0x2000
    CIM_INHERITED_FLAG = 0x4000

    CIM_TYPE_SINT8 = 16
    CIM_TYPE_UINT8 = 17
    CIM_TYPE_SINT16 = 2
    CIM_TYPE_UINT16 = 18
    CIM_TYPE_SINT32 = 3
    CIM_TYPE_UINT32 = 19
    CIM_TYPE_SINT64 = 20
    CIM_TYPE_UINT64 = 21
    CIM_TYPE_REAL32 = 4
    CIM_TYPE_REAL64 = 5
    CIM_TYPE_BOOLEAN = 11
    CIM_TYPE_STRING = 8
    CIM_TYPE_DATETIME = 101
    CIM_TYPE_REFERENCE = 102
    CIM_TYPE_CHAR16 = 103
    CIM_TYPE_OBJECT = 13
    CIM_ARRAY_SINT8 = 8208
    CIM_ARRAY_UINT8 = 8209
    CIM_ARRAY_SINT16 = 8194
    CIM_ARRAY_UINT16 = 8210
    CIM_ARRAY_SINT32 = 8195
    CIM_ARRAY_UINT32 = 8201
    CIM_ARRAY_SINT64 = 8202
    CIM_ARRAY_UINT64 = 8203
    CIM_ARRAY_REAL32 = 8196
    CIM_ARRAY_REAL64 = 8197
    CIM_ARRAY_BOOLEAN = 8203
    CIM_ARRAY_STRING = 8200
    CIM_ARRAY_DATETIME = 8293
    CIM_ARRAY_REFERENCE = 8294
    CIM_ARRAY_CHAR16 = 8295
    CIM_ARRAY_OBJECT = 8205

    CIM_TYPES_REF = {
        CIM_TYPE_SINT8: ('b', struct.calcsize('b')),
        CIM_TYPE_UINT8: ('B', struct.calcsize('B')),
        CIM_TYPE_SINT16: ('<h', struct.calcsize('<h')),
        CIM_TYPE_UINT16: ('<H', struct.calcsize('<H')),
        CIM_TYPE_SINT32: ('<l', struct.calcsize('<l')),
        CIM_TYPE_UINT32: ('<L', struct.calcsize('<L')),
        CIM_TYPE_SINT64: ('<q', struct.calcsize('<q')),
        CIM_TYPE_UINT64: ('<Q', struct.calcsize('<Q')),
        CIM_TYPE_REAL32: ('<f', struct.calcsize('<f')),
        CIM_TYPE_REAL64: ('<d', struct.calcsize('<d')),
        CIM_TYPE_BOOLEAN: ('<H', struct.calcsize('<H')),
        CIM_TYPE_STRING: ('<L', struct.calcsize('<L')),  # HEAPREF
        CIM_TYPE_DATETIME: ('<L', struct.calcsize('<L')),  # HEAPREF
        CIM_TYPE_REFERENCE: ('<L', struct.calcsize('<L')),  # HEAPREF
        CIM_TYPE_CHAR16: ('<H', struct.calcsize('<H')),
        CIM_TYPE_OBJECT: ('<L', struct.calcsize('<L')),  # HEAPREF
    }

    _CIM_TYPES_NAME = {
        CIM_TYPE_SINT8: 'sint8',
        CIM_TYPE_UINT8: 'uint8',
        CIM_TYPE_SINT16: 'sint16',
        CIM_TYPE_UINT16: 'uint16',
        CIM_TYPE_SINT32: 'sint32',
        CIM_TYPE_UINT32: 'uint32',
        CIM_TYPE_SINT64: 'sint64',
        CIM_TYPE_UINT64: 'uint64',
        CIM_TYPE_REAL32: 'real32',
        CIM_TYPE_REAL64: 'real64',
        CIM_TYPE_BOOLEAN: 'bool',
        CIM_TYPE_STRING: 'string',
        CIM_TYPE_DATETIME: 'datetime',
        CIM_TYPE_REFERENCE: 'reference',
        CIM_TYPE_CHAR16: 'char16',
        CIM_TYPE_OBJECT: 'object',
    }

    _CIM_TYPES_PYTYPE = {
        CIM_TYPE_SINT8: int,
        CIM_TYPE_UINT8: int,
        CIM_TYPE_SINT16: int,
        CIM_TYPE_UINT16: int,
        CIM_TYPE_SINT32: int,
        CIM_TYPE_UINT32: int,
        CIM_TYPE_SINT64: int,
        CIM_TYPE_UINT64: int,
        CIM_TYPE_REAL32: float,
        CIM_TYPE_REAL64: float,
        CIM_TYPE_BOOLEAN: bool,
        CIM_TYPE_STRING: str,
        CIM_TYPE_DATETIME: Union[datetime, timedelta],
        CIM_TYPE_REFERENCE: str,
        CIM_TYPE_CHAR16: str,
        CIM_TYPE_OBJECT: object,
    }

    @classmethod
    def get_value(cls, key: int, data: bytes, offset: int) -> Tuple[int, int]:
        fmt, size = cls.CIM_TYPES_REF[key]
        return struct.unpack_from(fmt, data, offset=offset)[0], offset + size

    @classmethod
    def get_cim_type_ref(cls, cim_type):
        p_type = \
            cim_type & (~(CimType.CIM_ARRAY_FLAG | CimType.CIM_INHERITED_FLAG))
        return cls.CIM_TYPES_REF[p_type]

    @classmethod
    def get_cim_type_name(cls, cim_type):
        p_type = \
            cim_type & (~(CimType.CIM_ARRAY_FLAG | CimType.CIM_INHERITED_FLAG))
        return cls._CIM_TYPES_NAME[p_type]

    @classmethod
    def get_cim_type_pytype(cls, cim_type) -> type:
        p_type = \
            cim_type & (~(CimType.CIM_ARRAY_FLAG | CimType.CIM_INHERITED_FLAG))
        return cls._CIM_TYPES_PYTYPE[p_type]
