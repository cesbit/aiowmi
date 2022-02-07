import calendar
import struct
import time

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


class AvPairs:

    PAIR_FMT = '<HH'
    PAIR_SIZE = struct.calcsize(PAIR_FMT)
    CIFS = 'cifs/'.encode('utf-16le')

    def __init__(self, data: bytes):
        self._pairs = [None] * 11
        ftype = 0xff
        offset = 0
        while ftype != NTLMSSP_AV_EOL:
            ftype, length = struct.unpack_from(self.PAIR_FMT, data, offset)
            offset += self.PAIR_SIZE
            self._pairs[ftype] = (length, data[offset: offset+length])
            offset += length

    def set_pair(self, ftype: int, content: bytes):
        self._pairs[ftype] = (len(content), content)

    def set_target_name(self):
        target_name = self.CIFS + self._pairs[NTLMSSP_AV_HOSTNAME][1]
        self.set_pair(NTLMSSP_AV_TARGET_NAME, target_name)

    def get_or_set_av_time(self) -> bytes:
        pair = self._pairs[NTLMSSP_AV_TIME]
        if pair is not None:
            return pair[1]

        av_time = struct.pack(
            '<q',
            (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))

        self.set_pair(NTLMSSP_AV_TIME, av_time)
        return av_time

    def get_data(self) -> bytes:
        data = []
        for (idx, pair) in enumerate((self._pairs)):
            if idx == NTLMSSP_AV_EOL or pair is None:
                continue

            ftype = idx
            length, content = pair

            data.append(struct.pack(self.PAIR_FMT, ftype, length))
            data.append(content)

        data.append(struct.pack('<HH', NTLMSSP_AV_EOL, 0))
        return b''.join(data)
