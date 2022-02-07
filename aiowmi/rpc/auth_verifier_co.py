import struct
from typing import Tuple

# typedef struct{
#   u_int8 [size_is(auth_pad_length)] auth_pad[]; /* align(4) */
#   u_int8 auth_type; /* :01 which authent service */
#   u_int8 auth_level; /* :01 which level within service */
#   u_int8 auth_pad_length; /* :01 */
#   u_int8 auth_reserved; /* :01 reserved, m.b.z. */
#   u_int32 auth_context_id; /* :04 */
#   u_int8 [size_is(auth_length)] auth_value[]; /* credentials */
# } auth_verifier_co_t;


class RpcAuthVerifierCo:
    __slots__ = (
        'auth_type',
        'auth_level',
        'auth_pad_length',
        'auth_context_id',
        'auth_value')

    AUTH_VERIFIER_CO_FMT = '<BBBBL'
    SIZE = struct.calcsize(AUTH_VERIFIER_CO_FMT)

    def __init__(self, data: bytes, auth_length: int, offset: int = 0):
        (
            self.auth_type,
            self.auth_level,
            self.auth_pad_length,
            reserved,
            self.auth_context_id,
        ) = struct.unpack_from(self.AUTH_VERIFIER_CO_FMT, data, offset)
        offset += self.SIZE
        self.auth_value = data[offset:offset+auth_length]

    @classmethod
    def make(
            cls,
            auth_type: int,
            auth_level: int,
            auth_pad_length: int,
            auth_context_id: int,
            auth_value: bytes) -> Tuple[bytes, int]:
        "Retruns the packet bytes and auth_length"
        padding = b'\xFF' * auth_pad_length

        return padding + struct.pack(
            cls.AUTH_VERIFIER_CO_FMT,
            auth_type,
            auth_level,
            auth_pad_length,
            0,  # reserved
            auth_context_id,
        ) + auth_value, len(auth_value)
