from typing import Union
from datetime import datetime, timedelta


_FMT = '%Y%m%d%H%M%S.%f'


def dt_from_str(s: str) -> Union[datetime, timedelta]:
    """String to datetime.

    https://www.dmtf.org/sites/default/files/standards/documents/DSP0004V2.3_final.pdf
    """  # nopep8
    s = s.replace('*', '0')

    if s.endswith(':000'):
        # ddddddddhhmmss.mmmmmm:000
        return timedelta(
            days=int(s[:8]),
            hours=int(s[8:10]),
            minutes=int(s[10:12]),
            seconds=int(s[12:14]),
            microseconds=int(s[15:21])
        )

    # timestamp: yyyymmddhhmmss.mmmmmmsutc
    # utc is offset in minutes
    minutes = int(s[-3:])
    hours = minutes // 60
    minutes = minutes % 60

    for t in (4, 6):
        # months and days must start at 1, not 0
        e = t + 2
        if s[t:e] == '00':
            s = s[:t] + '01' + s[e:]

    dt = datetime.strptime(s[:21], _FMT)
    if s[-4] == '+':
        dt -= timedelta(hours=hours, minutes=minutes)
    else:
        assert s[-4] == '-'
        dt += timedelta(hours=hours, minutes=minutes)
    return dt


if __name__ == '__main__':
    print(dt_from_str('20220207094949.500000+060'))
    print(dt_from_str('19980525133015.0000000-300'))
    print(dt_from_str('19980525183015.0000000+000'))
    print(dt_from_str('19980525******.0000000+000'))
    print(dt_from_str('1998**********.0000000+000'))
    print(dt_from_str('00000001132312.125***:000'))
