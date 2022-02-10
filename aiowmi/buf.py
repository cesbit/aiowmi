from typing import Union


class Buf:
    __slots__ = ('data', 'size', 'call_id')

    def __init__(self, size: int, call_id: int):
        self.data = b''
        self.size = size
        self.call_id = call_id

    def append(self, data: bytes) -> Union[bool, bytes]:
        """Returns bytes when the buffer is complete, or False if not."""
        self.data += data
        n = len(self.data)

        if n == self.size:
            return b''

        if n > self.size:
            more = self.data[self.size:]
            self.data = self.data[:self.size]
            return more

        return False
