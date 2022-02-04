NTLM_AUTH_NONE = 1
NTLM_AUTH_CONNECT = 2
NTLM_AUTH_CALL = 3
NTLM_AUTH_PKT = 4
NTLM_AUTH_PKT_INTEGRITY = 5
NTLM_AUTH_PKT_PRIVACY = 6

# If set, requests 56-bit encryption. If the client sends NTLMSSP_
# NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN
# with NTLMSSP_NEGOTIATE_56 to the server in the NEGOTIATE_MESSAGE, the server
# MUST return NTLMSSP_NEGOTIATE_56 to
# the client in the CHALLENGE_MESSAGE. Otherwise it is ignored. If both
# NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128
# are requested and supported by the client and server, NTLMSSP_NEGOTIATE_56
# and NTLMSSP_NEGOTIATE_128 will both be
# returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL
# SHOULD set NTLMSSP_NEGOTIATE_56 if it is
# supported. An alternate name for this field is NTLMSSP_NEGOTIATE_56.
NTLMSSP_NEGOTIATE_56 = 0x80000000

# If set, requests an explicit key exchange. This capability SHOULD be used
# because it improves security for message
# integrity or confidentiality. See sections 3.2.5.1.2, 3.2.5.2.1,
# and 3.2.5.2.2 for details. An alternate name for
# this field is NTLMSSP_NEGOTIATE_KEY_EXCH.
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000

# If set, requests 128-bit session key negotiation. An alternate name for this
# field is NTLMSSP_NEGOTIATE_128.
# If the client sends NTLMSSP_NEGOTIATE_128 to the server in
# the NEGOTIATE_MESSAGE, the server MUST return
# NTLMSSP_NEGOTIATE_128 to the client in the CHALLENGE_MESSAGE only if the
# client sets NTLMSSP_NEGOTIATE_SEAL or
# NTLMSSP_NEGOTIATE_SIGN. Otherwise it is ignored.
# If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are
# requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and
# NTLMSSP_NEGOTIATE_128 will both be
# returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL
# SHOULD set NTLMSSP_NEGOTIATE_128 if it
# is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_128
NTLMSSP_NEGOTIATE_128 = 0x20000000

NTLMSSP_RESERVED_1 = 0x10000000
NTLMSSP_RESERVED_2 = 0x08000000
NTLMSSP_RESERVED_3 = 0x04000000

# If set, requests the protocol version number. The data corresponding to this
# flag is provided in the Version field
# of the NEGOTIATE_MESSAGE, the CHALLENGE_MESSAGE, and
# the AUTHENTICATE_MESSAGE. <22> An alternate name for this field
# is NTLMSSP_NEGOTIATE_VERSION
NTLMSSP_NEGOTIATE_VERSION = 0x02000000
NTLMSSP_RESERVED_4 = 0x01000000

# If set, indicates that the TargetInfo fields in the
# CHALLENGE_MESSAGE (section 2.2.1.2) are populated.
# An alternate name for this field is NTLMSSP_NEGOTIATE_TARGET_INFO.
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000

# If set, requests the usage of the LMOWF (section 3.3). An alternate name
# for this field is
# NTLMSSP_REQUEST_NON_NT_SESSION_KEY.
NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000
NTLMSSP_RESERVED_5 = 0x00200000

# If set, requests an identify level token. An alternate name for this field
# is NTLMSSP_NEGOTIATE_IDENTIFY
NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000

# If set, requests usage of the NTLM v2 session security. NTLM v2 session
# security is a misnomer because it is not
# NTLM v2. It is NTLM v1 using the extended session security that is also
# in NTLM v2. NTLMSSP_NEGOTIATE_LM_KEY and
# NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If
# both NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
# and NTLMSSP_NEGOTIATE_LM_KEY are requested,
#  NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the
# client. NTLM v2 authentication session key generation MUST be supported by
# both the client and the DC in order to be
# used, and extended session security signing and sealing requires support
# from the client and the server in order to
# be used.<23> An alternate name for this field is
# NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_NTLM2 = 0x00080000
NTLMSSP_TARGET_TYPE_SHARE = 0x00040000

# If set, TargetName MUST be a server name. The data corresponding to this
# flag is provided by the server in the
# TargetName field of the CHALLENGE_MESSAGE. If this bit is set, then
# NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set.
# This flag MUST be ignored in the NEGOTIATE_MESSAGE and the
# AUTHENTICATE_MESSAGE. An alternate name for this field
# is NTLMSSP_TARGET_TYPE_SERVER
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000

# If set, TargetName MUST be a domain name. The data corresponding to this
# flag is provided by the server in the
# TargetName field of the CHALLENGE_MESSAGE. If set, then
# NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set. This flag MUST
# be ignored in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE.
# An alternate name for this field is
# NTLMSSP_TARGET_TYPE_DOMAIN.
NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000

# If set, requests the presence of a signature block on all messages.
# NTLMSSP_NEGOTIATE_ALWAYS_SIGN MUST be set in the
# NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client.
# NTLMSSP_NEGOTIATE_ALWAYS_SIGN is overridden
# by NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL, if they are supported.
# An alternate name for this field is
# NTLMSSP_NEGOTIATE_ALWAYS_SIGN.
# forces the other end to sign packets
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
NTLMSSP_RESERVED_6 = 0x00004000

# This flag indicates whether the Workstation field is present. If this flag
# is not set, the Workstation field MUST be
# ignored. If this flag is set, the length field of the Workstation field
# specifies whether the workstation name is
# nonempty or not.<24> An alternate name for this field is
# NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000

# If set, the domain name is provided (section 2.2.1.1).<25> An alternate name
# for this field is
# NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x00001000

# If set, the connection SHOULD be anonymous
NTLMSSP_NEGOTIATE_ANONYMOUS = 0x00000800

# If set, LM authentication is not allowed and only NT authentication is used.
NTLMSSP_NEGOTIATE_NT_ONLY = 0x00000400

# If set, requests usage of the NTLM v1 session security protocol.
# NTLMSSP_NEGOTIATE_NTLM MUST be set in the
# NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client.
# An alternate name for this field is
# NTLMSSP_NEGOTIATE_NTLM
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_RESERVED_8 = 0x00000100

# If set, requests LAN Manager (LM) session key computation.
# NTLMSSP_NEGOTIATE_LM_KEY and
# NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both
# NTLMSSP_NEGOTIATE_LM_KEY and
# NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested,
# NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be
# returned to the client. NTLM v2 authentication session key generation MUST
# be supported by both the client and the
# DC in order to be used, and extended session security signing and sealing
# requires support from the client and the
# server to be used. An alternate name for this field is
# NTLMSSP_NEGOTIATE_LM_KEY.
NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080

# If set, requests connectionless authentication.
# If NTLMSSP_NEGOTIATE_DATAGRAM is set, then NTLMSSP_NEGOTIATE_KEY_EXCH
# MUST always be set in the AUTHENTICATE_MESSAGE to the server and the
# CHALLENGE_MESSAGE to the client. An alternate
# name for this field is NTLMSSP_NEGOTIATE_DATAGRAM.
NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040

# If set, requests session key negotiation for message confidentiality.
# If the client sends NTLMSSP_NEGOTIATE_SEAL to
# the server in the NEGOTIATE_MESSAGE, the server MUST return
# NTLMSSP_NEGOTIATE_SEAL to the client in the
# CHALLENGE_MESSAGE. Clients and servers that set
# NTLMSSP_NEGOTIATE_SEAL SHOULD always set NTLMSSP_NEGOTIATE_56 and
# NTLMSSP_NEGOTIATE_128, if they are supported. An alternate name for this
# field is NTLMSSP_NEGOTIATE_SEAL.
NTLMSSP_NEGOTIATE_SEAL = 0x00000020

# If set, requests session key negotiation for message signatures. If the
# client sends NTLMSSP_NEGOTIATE_SIGN to the
# server in the NEGOTIATE_MESSAGE, the server MUST return
# NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE.
# An alternate name for this field is NTLMSSP_NEGOTIATE_SIGN.
# means packet is signed, if verifier is wrong it fails
NTLMSSP_NEGOTIATE_SIGN = 0x00000010
NTLMSSP_RESERVED_9 = 0x00000008

# If set, a TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST
# be supplied. An alternate name for this
# field is NTLMSSP_REQUEST_TARGET.
NTLMSSP_REQUEST_TARGET = 0x00000004

# If set, requests OEM character set encoding. An alternate name for this
# field is NTLM_NEGOTIATE_OEM. See bit A for
# details.
NTLM_NEGOTIATE_OEM = 0x00000002

# If set, requests Unicode character set encoding. An alternate name for
# this field is NTLMSSP_NEGOTIATE_UNICODE.
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001

# AV_PAIR constants
NTLMSSP_AV_EOL = 0x00
NTLMSSP_AV_HOSTNAME = 0x01
NTLMSSP_AV_DOMAINNAME = 0x02
NTLMSSP_AV_DNS_HOSTNAME = 0x03
NTLMSSP_AV_DNS_DOMAINNAME = 0x04
NTLMSSP_AV_DNS_TREENAME = 0x05
NTLMSSP_AV_FLAGS = 0x06
NTLMSSP_AV_TIME = 0x07
NTLMSSP_AV_RESTRICTIONS = 0x08
NTLMSSP_AV_TARGET_NAME = 0x09
NTLMSSP_AV_CHANNEL_BINDINGS = 0x0a

NTLMSSP_REVISION_W2K3 = 0x0F  # Version 15 of the NTLMSSP is in use.
