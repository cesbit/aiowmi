[![CI](https://github.com/cesbit/aiowmi/workflows/CI/badge.svg)](https://github.com/cesbit/aiowmi/actions)
[![Release Version](https://img.shields.io/github/release/cesbit/aiowmi)](https://github.com/cesbit/aiowmi/releases)


# Python WMI

Windows Management Interface connector using asyncio for the Python language.

**Supports:**
- [x] NTLM Authentication
- [x] WMI Query (IWbemServices_ExecQuery)
- [x] Parsing of basic WMI Objects (int/float/str/datetime/array/references)
- [x] Optimized queries using the SmartEnum implementation

**Todo:**
- [ ] Kerberos Authentication
- [ ] Async WMI Query (IWbemServices_ExecQueryAsync)
- [ ] Other DCOM/RPC/WMI calls?
- [ ] Support for WMI Methods?
- [ ] Improve documentation

## Usage

The example below covers most of what is suppored by this library:

```python

import asyncio
import logging
import time
from aiowmi.connection import Connection
from aiowmi.query import Query
from aiowmi.exceptions import WbemStopIteration
from aiowmi.exceptions import ServerNotOptimized


async def main():

    host = '10.0.0.1'  # ip address or hostname or fqdn
    username = 'username'
    password = 'password'
    domain = ''  # optional domain name

    # Query has a default namespace 'root/cimv2'
    queries = (
        Query('SELECT * FROM Win32_OperatingSystem', namespace='root/cimv2'),
        Query('SELECT * FROM Win32_NetworkAdapter'),
        Query('SELECT * FROM Win32_LoggedOnUser'),
        Query('SELECT * FROM Win32_PnpEntity'),
        Query('SELECT Caption, Description, InstallDate, InstallDate2, '
              'InstallLocation, InstallSource, InstallState, Language, '
              'LocalPackage, Name, PackageCache, PackageCode, PackageName, '
              'ProductID, RegCompany, RegOwner, SKUNumber, Transforms, '
              'URLInfoAbout, URLUpdateInfo, Vendor, Version '
              'FROM Win32_Product'),
        Query('SELECT Name, DiskReadsPersec, DiskWritesPersec '
              'FROM Win32_PerfFormattedData_PerfDisk_LogicalDisk'),
    )

    start = time.time()

    conn = Connection(host, username, password, domain=domain)
    service = None
    await conn.connect()
    try:
        service = await conn.negotiate_ntlm()

        for query in queries:
            print(f"""
###############################################################################
# Start Query: {query.query}
###############################################################################
""")
            try:
                await query.start(conn, service)

                # Try to use smart queries to reduce the network traffic size
                # If the server does not support optimization,
                # the ServerNotOptimized exception is raised.
                try:
                    await query.optimize()
                except ServerNotOptimized:
                    pass  # We are not able to use optimized queries

                while True:
                    try:
                        res = await query.next()
                    except WbemStopIteration:
                        break

                    # Function `get_properties(..)` accepts a few keyword
                    # arguments:
                    #
                    # ignore_defaults:
                    #        Ignore default values. Set missing values to None
                    #        if a value does not exist in the current class.
                    #        ignore_defaults will always be True if
                    #        ignore_missing is set to True.
                    # ignore_missing:
                    #       If set to True, values missing in the current class
                    #       will not be part of the result.
                    # load_qualifiers:
                    #       Load the qualifiers of the properties. If False,
                    #       the property qualifier_set will have the offset
                    #       in the heap where the qualifiers are stored.
                    #
                    props = res.get_properties()

                    for name, prop in props.items():
                        print(name, '\n\t', prop.value)

                        if prop.is_reference():
                            # References can easy be queried using the
                            # get_reference(..) function. The function accepts
                            # a keyword argument `filter_props=[..]` with an
                            # optional list of properties to query. If omitted,
                            #  the function returns all (*) properties.
                            res = await prop.get_reference(service)
                            ref_props = res.get_properties(ignore_missing=True)
                            for name, prop in ref_props.items():
                                print('\t\t', name, '\n\t\t\t', prop.value)

                    print(f"""
----------------------------------- End Item ----------------------------------
""")
            finally:
                await query.done()  # clean up memory
    finally:
        if service:
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
