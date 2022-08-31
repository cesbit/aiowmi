import struct


class DualStringArray:

    __slots__ = (
        'w_num_entries',
        'w_security_offset',
        'string_binding',
        'sec_binding',
    )

    DUALSTRING_FMT = '<HH'

    DUALSTRING_FMT_SZ = struct.calcsize(DUALSTRING_FMT)

    @classmethod
    def from_data(cls, data: bytes, offset: int) -> 'DualStringArray':
        self = cls()

        # w_num_entries: number of unsigned shorts from the first
        # entry in the StringBinding array to the end of the buffer.
        # w_security_offset: number of unsigned shorts from the first entry in
        # the StringBinding array to the first entry in the SecBinding array
        (
            cls.w_num_entries,
            cls.w_security_offset,
        ) = struct.unpack_from(cls.DUALSTRING_FMT, data, offset=offset)
        offset += cls.DUALSTRING_FMT_SZ

        end = offset + cls.w_num_entries * 2
        end_string_binding = offset + cls.w_security_offset * 2

        cls.string_binding = data[offset:end_string_binding]
        cls.sec_binding = data[end_string_binding:end]

        return self, end

    def get_data(self) -> bytes:
        return struct.pack(
            self.DUALSTRING_FMT,
            self.w_num_entries,
        ) + self.string_binding + self.sec_binding
