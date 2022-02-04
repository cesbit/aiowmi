from abc import ABC


class NdrInfoData(ABC):
    CLSID: str

    def get_data() -> bytes:
        pass
