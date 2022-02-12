import struct
from .version import NTLMVersion
from .const import (
    NTLMSSP_NEGOTIATE_128,
    NTLMSSP_NEGOTIATE_56,
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
    NTLMSSP_NEGOTIATE_NTLM,
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED,
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
    NTLMSSP_NEGOTIATE_SEAL,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMSSP_NEGOTIATE_TARGET_INFO,
    NTLMSSP_NEGOTIATE_UNICODE,
    NTLMSSP_NEGOTIATE_VERSION,
    NTLMSSP_REQUEST_TARGET,
)

# [MS-NLMP.pdf]  2.2.1.1 NEGOTIATE_MESSAGE
# {
#   fixed:                      NTLMSSP + \0
#   message_type:               <L MUST be 1
#   negotiate_flags:            <L flags
#   domain_name_len:            <H len domain name
#   domain_name_max_len:        <H Equal to  domain_name_len
#   domain_name_offset:         <L Offset to buffer in payload, from begin
#   workstation_name_len:       <H len workstation name
#   workstation_name_max_len:   <H Equal to workstation_name_len
#   workstation_name_offset:    <L Offset to buffer in payload, from begin
#   version:                    Optional 8 bytes (Version structure)
#   payload {
#       domain_name,
#       workstation_name,
#   }
# }


class NTLMAuthNegotiate:
    """Message from client to server."""

    SIGNATURE = b'NTLMSSP\x00'
    SIGNATURE_LEN = len(SIGNATURE)
    MESSAGE_TYPE = 1
    NEGOTIATE_FMT = '<LLHHLHHL'
    NEGOTIATE_SIZE = SIGNATURE_LEN + struct.calcsize(NEGOTIATE_FMT)

    def __init__(self):
        self._negotiate_flags = (
            # Sign in required flags
            NTLMSSP_NEGOTIATE_KEY_EXCH |
            NTLMSSP_NEGOTIATE_SIGN |
            NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
            NTLMSSP_NEGOTIATE_SEAL |
            # NTLM v2 flags
            NTLMSSP_NEGOTIATE_TARGET_INFO |
            # Always
            NTLMSSP_NEGOTIATE_NTLM |
            NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
            NTLMSSP_NEGOTIATE_UNICODE |
            NTLMSSP_REQUEST_TARGET |
            NTLMSSP_NEGOTIATE_128 |
            NTLMSSP_NEGOTIATE_56)
        self._version = b''
        self._version_len = 0
        self._domain_name = b''
        self._domain_name_len = 0
        self._workstation_name = b''
        self._workstation_name_len = 0

    def get_negotiate_flags(self):
        return self._negotiate_flags

    def set_version(self, version: NTLMVersion):
        """Version is packed as 8 bytes.
        So:
          len(self._version) ==  NTLMVersion.VERSION_SIZE == 8 bytes
        """
        self._version = version.get_data()
        self._version_len = NTLMVersion.VERSION_SIZE
        self._negotiate_flags |= NTLMSSP_NEGOTIATE_VERSION

    def set_domain_name(self, domain_name):
        self._domain_name = domain_name.encode('utf-16le')
        self._domain_name_len = len(self._domain_name)
        self._negotiate_flags |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED

    def set_workstation_name(self, workstation_name):
        self._workstation_name = workstation_name.encode('utf-16le')
        self._workstation_name_len = len(self._workstation_name)
        self._negotiate_flags |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

    def get_data(self) -> bytes:
        domain_name_offset = self.NEGOTIATE_SIZE + self._version_len
        workstation_name_offset = domain_name_offset + self._domain_name_len

        data = self.SIGNATURE + struct.pack(
            self.NEGOTIATE_FMT,
            self.MESSAGE_TYPE,
            self._negotiate_flags,
            self._domain_name_len,
            self._domain_name_len,  # max must be equal to len
            domain_name_offset,
            self._workstation_name_len,
            self._workstation_name_len,  # max must be equal to len
            workstation_name_offset,
        ) + self._version + self._domain_name + self._workstation_name
        return data
