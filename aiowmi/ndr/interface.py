from abc import ABC, abstractmethod


class NdrInterface(ABC):

    @abstractmethod
    def get_ipid(self) -> int:
        ...
