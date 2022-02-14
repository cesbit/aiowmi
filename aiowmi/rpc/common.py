import struct
from .const import MSRPC_REQUEST, PFC_FIRST_FRAG, PFC_LAST_FRAG

# typedef struct {
#   u_int8 rpc_vers = 5;        /* 00:01 RPC version */
#   u_int8 rpc_vers_minor ;     /* 01:01 minor version */
#   u_int8 PTYPE = bind_nak;    /* 02:01 bind nak PDU */
#   u_int8 pfc_flags;           /* 03:01 flags */
#   byte packed_drep[4];        /* 04:04 NDR data rep format label*/
#   u_int16 frag_length;        /* 08:02 total length of fragment */
#   u_int16 auth_length;        /* 10:02 length of auth_value */
#   u_int32 call_id;            /* 12:04 call identifier */
# }


class RpcCommon:

    COMMON_FMT = '<BBBBLHHL'
    COMMON_SIZE = struct.calcsize(COMMON_FMT)  # 16

    def init(self, ptype: int = None):
        self._rpc_vers = 5
        self.rpc_vers_minor = 0
        self.ptype = ptype
        self.pfc_flags = PFC_FIRST_FRAG | PFC_LAST_FRAG

        #  this field has documentation in c706.pdf,
        #  14.1, Data Representation Format Label
        #   Character: ASCII
        #   Floating point: IEEE
        self.packed_drep = 0x10

        self.frag_length = self.COMMON_SIZE
        self.auth_length = 0
        self.call_id = 1

        self._pdu_data = b''
        self._pdu_data_len = 0
        self._auth_verifier = b''

    @classmethod
    def from_data(cls, data: bytes):
        rpc_common = cls()
        (
            rpc_common._rpc_vers,
            rpc_common.rpc_vers_minor,
            rpc_common.ptype,
            rpc_common.pfc_flags,
            rpc_common.packed_drep,
            rpc_common.frag_length,
            rpc_common.auth_length,
            rpc_common.call_id,
        ) = struct.unpack_from(cls.COMMON_FMT, data, 0)
        return rpc_common

    def set_pdu_data(self, pdu_data: bytes) -> int:
        # May be called a second time, for example plain data and later
        # with encrypted data. If so, we first need to decrement the previous
        # pdu_data_len from the fragment size.
        self.frag_length -= self._pdu_data_len
        self._pdu_data = pdu_data
        self._pdu_data_len = len(pdu_data)
        self.frag_length += self._pdu_data_len
        return self._pdu_data_len

    def set_auth_verifier(
                self, auth_verifier: bytes, auth_length: int) -> None:
        """auth_verifier, auth_length data can be created using:
            RpcAuthVerifierCo.make(..).
        """
        assert self.auth_length == 0
        self._auth_verifier = auth_verifier
        self.auth_length = auth_length
        self.frag_length += len(auth_verifier)

    def set_auth_data(self, auth_data: bytes):
        assert self.auth_length == len(auth_data)
        self._auth_verifier = \
            self._auth_verifier[:-self.auth_length] + auth_data

    def get_common_data(self) -> bytes:
        return struct.pack(
            self.COMMON_FMT,
            self._rpc_vers,             # 1. B
            self.rpc_vers_minor,        # 2. B
            self.ptype,                 # 3. B
            self.pfc_flags,             # 4. B
            self.packed_drep,           # 5. <L
            self.frag_length,           # 6. <H
            self.auth_length,           # 7. <H
            self.call_id,               # 8. <L
        )

    def get_data(self) -> bytes:
        return self.get_common_data() + self._pdu_data + self._auth_verifier
