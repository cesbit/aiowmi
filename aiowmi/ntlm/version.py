import struct
from .const import NTLMSSP_REVISION_W2K3


class NTLMVersion:

    VERSION_FMT = "<BBHBBBB"
    VERSION_SIZE = struct.calcsize(VERSION_FMT)

    def __init__(self, major, minor, build):
        """[MS-NLMP] 2.2.2.10 VERSION."""
        self.product_major_version = major
        self.product_minor_version = minor
        self.product_build = build
        self.reserved = 0  # must be ignored
        self.ntlm_revision_current = NTLMSSP_REVISION_W2K3

    def get_data(self) -> bytes:
        return struct.pack(
            self.VERSION_FMT,
            self.product_major_version,
            self.product_minor_version,
            self.product_build,
            self.reserved,
            self.reserved,
            self.reserved,
            self.ntlm_revision_current)
