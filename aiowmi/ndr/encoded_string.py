from typing import Tuple
from itertools import chain


class EncodedString:

    # 2.2.78 Encoded-String [MS-WMIO]

    @staticmethod
    def from_data(data, offset) -> Tuple[str, int]:
        flags = data[offset]
        offset += 1
        if flags == 0:
            # COMPRESSED UNICODE (UTF-16le)
            end = data.find(b'\x00', offset)
            raw = data[offset:end]
            try:
                s = raw.decode('ascii')  # fast, works 99.9% of the time
            except UnicodeDecodeError:
                n = len(raw)
                s = bytes(chain(*zip(raw, b'\x00'*n))).decode('utf-16le')

            return s, end + 1

        # UNICODE
        end = data.find(b'\x00\x00')

        raw = data[offset: end + (end - offset) % 2]
        return raw.decode('utf-16le'), end + 2
