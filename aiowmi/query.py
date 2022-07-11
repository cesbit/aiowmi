import asyncio
import logging
from typing import TYPE_CHECKING
from .const import WBEM_INFINITE
from .const import WBEM_FLAG_FORWARD_ONLY
from .const import WBEM_FLAG_RETURN_IMMEDIATELY
from .dtypes.wordstr import WORDSTR
from .qcontext import QContext


if TYPE_CHECKING:
    from .protocol import Protocol
    from .connection import Connection


class Query:

    _WQL = WORDSTR('WQL')

    def __init__(
            self,
            query: str,
            namespace: str = 'root/cimv2',
            language: str = None):
        if not namespace.startswith('//'):
            namespace = '//./' + namespace
        self.query = query
        self.namespace = namespace
        self._query = WORDSTR(query)
        self._language = self._WQL if language is None else WORDSTR(language)

    def context(
            self,
            conn: 'Connection',
            proto: 'Protocol',
            flags: int = (
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY),
            timeout: int = 60,
            skip_optimize: bool = False):
        """IWbemServices_ExecQuery.
        3.1.4.3.18 IWbemServices::ExecQuery (Opnum 20) [MS-WMI]

        Optional flags: (import from aiowmi.const)

        WBEM_FLAG_USE_AMENDED_QUALIFIERS (0x00020000)
            If this bit is not set, the server SHOULD not return CIM
            localizable information.
            If this bit is set, the server SHOULD return CIM localizable
            information for the CIM object, as specified in section 2.2.6.
        WBEM_FLAG_RETURN_IMMEDIATELY (0x00000010)
            If this bit is not set, the server MUST make the method
            call synchronously. If this bit is set, the server MUST make the
            method call semisynchronously.
        WBEM_FLAG_DIRECT_READ (0x00000200)
            If this bit is not set, the server MUST consider the entire
            class hierarchy when it returns the result.
            If this bit is set, the server MUST disregard any derived
            class when it searches the result.
        WBEM_FLAG_PROTOTYPE (0x00000002)
            If this bit is not set, the server MUST run the query.
            If this bit is set, the server MUST only return the class
        WBEM_FLAG_FORWARD_ONLY (0x00000020)
            If this bit is not set, the server MUST return an
            enumerator that has reset capability.
            If this bit is set, the server MUST return an enumerator
            without reset capability, as specified in section
        """
        return QContext(self, conn, flags, proto, timeout, skip_optimize)

    async def start(
            self,
            conn: 'Connection',
            proto: 'Protocol',
            flags: int = (
                WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY),
            timeout: int = 60):
        self._qc = QContext(self, conn, flags, proto, timeout, True)
        await self._qc.start()

    def optimize(self) -> asyncio.Future:
        return self._qc.optimize()

    def next(self, timeout: int = WBEM_INFINITE) -> asyncio.Future:
        return self._qc.next()

    def done(self) -> asyncio.Future:
        qc, self._qc = self._qc, None
        return qc.release()
