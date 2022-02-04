# Python WMI

Asynchronous Windows Management Interface connector for the Python language.


```python

import asyncio
import logging
import time
from aiowmi.connection import Connection
from aiowmi.query import Query
from aiowmi.exceptions import WbemStopIteration


async def main():

    host = '10.0.0.1'  # ip address, TODO: test with host name
    username = 'username'  # TODO: test with domain user
    password = 'password'

    queries = (
        Query('SELECT * FROM Win32_OperatingSystem'),
        Query('SELECT * FROM Win32_NetworkAdapter'),
        Query('SELECT * FROM Win32_LoggedOnUser'),
        Query('SELECT * FROM Win32_PnpEntity'),
        # Query('SELECT Caption, Description, InstallDate, InstallDate2, '
        #       'InstallLocation, InstallSource, InstallState, Language, '
        #       'LocalPackage, Name, PackageCache, PackageCode, PackageName, '
        #       'ProductID, RegCompany, RegOwner, SKUNumber, Transforms, '
        #       'URLInfoAbout, URLUpdateInfo, Vendor, Version '
        #       'FROM Win32_Product'),
        # Query('SELECT Name, DiskReadsPersec, DiskWritesPersec '
        #       'FROM Win32_PerfFormattedData_PerfDisk_LogicalDisk'),
    )

    start = time.time()

    conn = Connection(host, username, password)
    await conn.connect()
    try:
        service = await conn.negotiate_ntlm()
        for query in queries:
            print(f"""
###############################################################################
# Start Query: {query.query}
###############################################################################
""")
            await query.start(service)

            while True:
                try:
                    res = await query.next()
                except WbemStopIteration:
                    break

                props = res.get_properties(ignore_missing=True)

                for name, prop in props.items():
                    print(name, '\n\t', prop.value)

                    if prop.is_reference():
                        res = await prop.get_reference(service)
                        ref_props = res.get_properties(ignore_missing=True)
                        for name, prop in ref_props.items():
                            print('\t\t', name, '\n\t\t\t', prop.value)

                print(f"""
----------------------------------- End Item ----------------------------------
""")
    except Exception:
        raise
    finally:
        service.close()
        conn.close()
        end = time.time()
        print('done in ', end-start)

if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
            fmt='[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d] ' +
                '%(message)s',
            datefmt='%y%m%d %H:%M:%S',
            style='%')

    ch.setFormatter(formatter)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())


```