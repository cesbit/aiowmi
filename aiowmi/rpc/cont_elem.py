import struct

# struct {
#   p_context_id_t p_cont_id; (u_int16)
#   u_int8 n_transfer_syn; /* number of items */
#   u_int8 reserved; /* alignment pad, m.b.z. */
#   p_syntax_id_t abstract_syntax; /* transfer syntax list */
#   p_syntax_id_t [size_is(n_transfer_syn)] transfer_syntaxes[];
# } p_cont_elem_t


class RpcContElem:
    FMT = '<HBB'

    def __init__(self, abstract_syntax):
        # this is the context Id, the index number in the parent list
        self.p_cont_id = None

        self._n_transfer_syn = 0
        self._reserved = 0
        self._abstract_syntax = abstract_syntax
        self._transfer_syntaxes = []

    def add_transfer_syntax(self, transfer_syntax):
        self._transfer_syntaxes.append(transfer_syntax)
        self._n_transfer_syn += 1

    def get_data(self):
        return struct.pack(
            self.FMT,
            self.p_cont_id,
            self._n_transfer_syn,
            self._reserved
        ) + self._abstract_syntax + b''.join(self._transfer_syntaxes)
