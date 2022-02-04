import struct
from .version import NTLMVersion
from .const import (
    NTLMSSP_NEGOTIATE_128,
    NTLMSSP_NEGOTIATE_56,
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
    NTLMSSP_NEGOTIATE_KEY_EXCH,
    NTLMSSP_NEGOTIATE_NTLM,
    NTLMSSP_NEGOTIATE_SEAL,
    NTLMSSP_NEGOTIATE_SIGN,
    NTLMSSP_NEGOTIATE_TARGET_INFO,
    NTLMSSP_NEGOTIATE_UNICODE,
    NTLMSSP_REQUEST_TARGET,
    NTLMSSP_NEGOTIATE_VERSION,
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED,
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
)

# [MS-NLMP.pdf]  2.2.1.2 CHALLENGE_MESSAGE
# {
#   fixed:                      NTLMSSP + \0
#   message_type:               <L MUST be 1
#   target_name_len:            <H len domain name
#   target_name_max_len:        <H Equal to  domain_name_len
#   target_name_offset:         <L Offset to buffer in payload, from begin
#   negotiate_flags:            <L flags
#   server_challenge:           <Q Random int (one time use)
#   reserved:                   <Q reserved
#   target_info_len:       <H len workstation name
#   target_info_max_len:   <H Equal to workstation_name_len
#   target_info_offset:    <L Offset to buffer in payload, from begin
#   version:               <Q Optional 8 bytes
#                               (Should be set when NTLMSSP_NEGOTIATE_VERSION)
#   payload {
#       target_name,
#       target_info,
#   }
# }


class NTLMAuthChallenge:
    """Message from server to client."""

    __slots__ = (
        'negotiate_flags',
        'server_challenge',
        'target_name',
        'target_info')

    SIGNATURE = b'NTLMSSP\x00'
    SIGNATURE_LEN = len(SIGNATURE)
    MESSAGE_TYPE = 2
    CHALLENGE_FMT = '<LHHLLQQHHL'
    CHALLENGE_SIZE = SIGNATURE_LEN + struct.calcsize(CHALLENGE_FMT)
    SERVER_CHALLENGE_OFFSET = SIGNATURE_LEN + struct.calcsize('<LHHLL')

    def __init__(self, data):
        assert data.startswith(self.SIGNATURE)
        offset = self.SIGNATURE_LEN
        (
            message_type,               # <L
            target_name_len,            # <H
            target_name_max_len,        # <H
            target_name_offset,         # <L
            self.negotiate_flags,       # <L
            server_challenge,           # <Q
            reserved,                   # <Q
            target_info_len,            # <H
            target_info_max_len,        # <H
            target_info_offset,         # <L
        ) = struct.unpack_from(self.CHALLENGE_FMT, data, offset)

        self.target_name = \
            data[target_name_offset:target_name_offset+target_name_len]
        self.target_info = \
            data[target_info_offset:target_info_offset+target_info_len]
        self.server_challenge = data[
            self.SERVER_CHALLENGE_OFFSET: self.SERVER_CHALLENGE_OFFSET+8]
