import struct
from typing import Optional
from ..ndr.orpcthis import ORPCTHIS
from ..dtypes.lpwstr import LPWSTR
from ..ndr.remote_create_instance_response import RemoteCreateInstanceResponse
from ..uuid import uuid_to_bin
from ..tools import get_null

"""
ORPCTHIS

version
\x05\x00\x07\x00
flags
\x00\x00\x00\x00
reserved
\x00\x00\x00\x00
cid
\xa7\xfd\xa2\x1c\xd4~\x83k\t\x16\x87XQ\xa5vO
extensions
\x00\x00\x00\x00

referent id (33379)
c\x82\x00\x00


wsz_network_resource

\x0f\x00\x00\x00
\x00\x00\x00\x00
\x0f\x00\x00\x00

string
/\x00/\x00.\x00/\x00r\x00o\x00o\x00t\x00/\x00c\x00i\x00m\x00v\x002\x00\x00\x00

padding
\xbf\xbf

null
\x00\x00\x00\x00
l_flags
\x00\x00\x00\x00
null
\x00\x00\x00\x00
"""


class NTLMLogin:

    FMT = '<l'

    def __init__(
            self,
            wsz_network_resource: str,
            wsz_preferred_locale: Optional[str] = None,
            p_ctx: Optional[bytes] = None):

        self.wsz_network_resource = LPWSTR(wsz_network_resource)
        self.wsz_preferred_locale = LPWSTR(wsz_preferred_locale)
        self.l_flags = 0
        self.p_ctx = get_null() if p_ctx is None else p_ctx

    def get_data(self) -> bytes:

        wsz_network_resource = self.wsz_network_resource.get_data()
        wsz_preferred_locale = self.wsz_preferred_locale.get_data()

        data = \
            ORPCTHIS.get_data() + \
            wsz_network_resource + \
            wsz_preferred_locale + \
            struct.pack(self.FMT, self.l_flags) + \
            self.p_ctx

        return data
