import logging
import struct
from ..exceptions import NoBindingException
from ..tools import is_fqdn, pad
from .activation_blob import ActivationBlob
from .interface import NdrInterface
from .objref_custom import ObjRefCustom
from .orpcthat import ORPCTHAT
from .props_out_info import PropsOutInfo
from .scm_reply_info_data import ScmReplyInfoData


class RemoteCreateInstanceResponse(NdrInterface):

    FMT1_32 = '<LLL'
    FMT1_64 = '<QLL'

    FMT1_32_SZ = struct.calcsize(FMT1_32)

    def __init__(self, target: str, data: bytes):
        self.orpcthat, offset = ORPCTHAT.from_data(data, offset=0)

        # activation_blobs
        (
            self.referent_id,
            _,
            size
        ) = struct.unpack_from(self.FMT1_32, data, offset)
        offset += self.FMT1_32_SZ

        self.objref = ObjRefCustom.from_data(data, offset, size)
        offset += size + pad(size)

        ab_data = ActivationBlob.from_data(self.objref.object_data)

        self.error_code, = struct.unpack_from('<L', data, offset)
        self.props_out_info = PropsOutInfo(ab_data.properties[0])
        self.scm_reply_info_data = ScmReplyInfoData(ab_data.properties[1])
        self._binding = None
        target = target.upper()
        self._target = target.partition('.')[0] if is_fqdn(target) else target

        assert self.error_code == 0, f'error code: {self.error_code}'

    def get_binding(self):
        if self._binding is None:
            for bindingtuple in self.scm_reply_info_data.str_bindings:
                tower_id, binding = bindingtuple
                if tower_id != 7:
                    continue

                if binding.find('[') >= 0:
                    binding, _, port = binding.strip(']\x00').partition('[')
                    port = int(port)
                else:
                    port = 0

                self._binding = (binding, port)

                if binding.upper().find(self._target) >= 0:
                    # take this binding, otherwise just the last one
                    break

        if self._binding is None:
            raise NoBindingException('no network binding has been found')

        logging.debug(f'selected binding: {self._binding}')
        return self._binding

    def get_ipid(self) -> int:
        return self.props_out_info.objref.ipid
