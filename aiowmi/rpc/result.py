import struct

# struct {
# p_cont_def_result_t result;

# p_provider_reason_t reason; /* only relevant if result !=
# * acceptance */
# p_syntax_id_t transfer_syntax;/* tr syntax selected
# * 0 if result not

# * accepted */
# } p_result_t;


class RpcResult:
    RESULT_LIST_FMT = '<BHH'  # result_n, reserved, reserved2
    RESULT_LIST_FMT_SIZE = struct.calcsize(RESULT_LIST_FMT)
