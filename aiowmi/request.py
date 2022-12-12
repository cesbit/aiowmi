import asyncio
from typing import Optional


class Request:

    def __init__(self, size: Optional[int] = None):
        self.buf = b''
        self.size = size
        self.fut = asyncio.Future()

    def done(self):
        if self.fut is not None:
            self.fut.cancel()
        self.fut = None

    async def readn(self, n: int, timeout: int = 5) -> bytes:
        assert self.fut is None

        data = self.buf[:n]
        self.buf = self.buf[n:]

        n -= len(data)
        if n:
            self.fut = asyncio.Future()
            self.size = n
            rest = await asyncio.wait_for(self.fut, timeout)
            data += rest

        return data
