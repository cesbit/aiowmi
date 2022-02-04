from ..tools import pad


class EncodedString:

    @staticmethod
    def from_data(data, offset) -> [str, int]:
        flags = data[offset]
        offset += 1
        if flags == 0:
            # ASCII
            end = data.find(b'\x00', offset)
            raw = data[offset:end]
            return raw.decode('ascii'), end + 1

        # assert (0)
        # UNICODE
        end = data.find(b'\x00\x00')

        raw = data[offset: end + (end - offset) % 2]
        return raw.decode('utf-16le'), end + 2
