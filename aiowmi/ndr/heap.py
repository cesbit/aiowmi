import struct
from typing import Tuple


class Heap:

    HEAP = '<L'
    HEAP_SZ = struct.calcsize(HEAP)

    @classmethod
    def from_data(cls, data: bytes, offset: int) -> Tuple[bytes, int]:
        # ClassHeap
        (
            heap_length,
        ) = struct.unpack_from(cls.HEAP, data, offset=offset)

        # HeapLength is a 32-bit value with the most significant bit always set
        # (using little-endian binary encoding for the 32-bit value), so that
        # the length is actually only 31 bits.
        heap_length &= 0x7fffffff
        offset += cls.HEAP_SZ

        heap = data[offset: offset + heap_length]
        offset += heap_length

        return heap, offset
