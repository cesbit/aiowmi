
class RpcBaseResp:
    def set_pdu_data_list(self, pdu_data_list: list):
        self._pdu_data_list = pdu_data_list

    def get_pdu_data_list(self) -> list:
        return self._pdu_data_list
