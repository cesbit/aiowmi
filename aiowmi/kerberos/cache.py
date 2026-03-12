import pickle
from logging import Logger
from typing import Optional


class KerberosCache:

    __slots__ = ('_file_path', '_tgs', '_tgt')

    def __init__(self, file_path: Optional[str] = None):
        """KerberosCacche: create an Instance per connection
        Argument `file_path` must be for example:

            /tmp/my-host.kerberos.cache.bin

        If None, memory is used (must keep the KerberosCache alive)
        """
        self._file_path = file_path
        self._tgt: Optional[tuple[bytes, bytes]] = None
        self._tgs: Optional[tuple[bytes, bytes]] = None

    def open(self, logger: Logger) -> tuple[
                Optional[tuple[bytes, bytes]],
                Optional[tuple[bytes, bytes]]]:
        if self._file_path is not None and \
                self._tgs is None or self._tgt is None:
            try:
                with open(self._file_path, 'rb') as fp:
                    dump = pickle.load(fp)
                self._tgt = dump[0], dump[1]
                self._tgs = dump[2], dump[3]
            except Exception:
                logger.warning(f'failed to load from: {self._file_path}')

        return self._tgt, self._tgs

    def write(self,
              tgt: tuple[bytes, bytes],
              tgs: tuple[bytes, bytes],
              logger: Logger):
        self._tgt = tgt
        self._tgs = tgs
        if self._file_path is not None:
            try:
                with open(self._file_path, 'wb') as fp:
                    pickle.dump(self._tgt + self._tgs, fp)
            except Exception as e:
                logger.warning(
                    f'failed to write to: {self._file_path}: {e}')
