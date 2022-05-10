import logging
from typing import Union
from datetime import datetime, timedelta


_FMT = '%Y%m%d%H%M%S.%f%z'


def dt_from_str(s: str) -> Union[datetime, timedelta]:
    """String to datetime.

    It's crap, but at least citrix may return invalid values like:
        00010101000000.000000+060

    Therefore, we try and when we fail, this function will return
     datetime.fromtimestamp(0) or timedelta(0). If you enable debug logging,
    the library will generate a log line when such an exception occurs.

    https://www.dmtf.org/sites/default/files/standards/documents/DSP0004V2.3_final.pdf
    """  # nopep8
    s = s.replace('*', '0')

    if s.endswith(':000'):
        # ddddddddhhmmss.mmmmmm:000
        try:
            td = timedelta(
                days=int(s[:8]),
                hours=int(s[8:10]),
                minutes=int(s[10:12]),
                seconds=int(s[12:14]),
                microseconds=int(s[15:21])
            )
        except Exception as e:
            logging.debug(
                f'invalid interval `{s}` ({e}); return timedelta(0)')
            td = timedelta(0)
        return td

    try:
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

        dt = datetime.strptime(f"{s[:21]}{s[-4]}{hours:02}{minutes:02}", _FMT)

    except Exception as e:
        logging.debug(
            f'invalid datetime `{s}` ({e}); '
            'return datetime.fromtimestamp(0)')
        dt = datetime.fromtimestamp(0)

    return dt


if __name__ == '__main__':
    print(dt_from_str('20220207094949.500000+060'))
    print(dt_from_str('19980525133015.0000000-300'))
    print(dt_from_str('19980525183015.0000000+000'))
    print(dt_from_str('19980525******.0000000+000'))
    print(dt_from_str('1998**********.0000000+000'))
    print(dt_from_str('00010000000000.0000000+300'))
    print(dt_from_str('00000000000000.0000000+300'))
    print(dt_from_str('00000001132312.125***:000'))
