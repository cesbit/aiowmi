import struct
import asyncio
from ..logger import logger


async def send_kerberos_packet(packet_bytes: bytes,
                               kdc_host: str, kdc_port: int = 88):
    logger.debug(f"Connecting to {kdc_host}:{kdc_port}...")
    reader, writer = await asyncio.open_connection(kdc_host, kdc_port)

    try:
        tcp_packet = struct.pack('>I', len(packet_bytes)) + packet_bytes
        # print(tcp_packet)
        # logger.debug(f"Sending {len(tcp_packet)} bytes...")
        writer.write(tcp_packet)
        await writer.drain()

        header = await reader.readexactly(4)
        resp_len = struct.unpack('>I', header)[0]
        logger.debug(f"KDC anwer of {resp_len} bytes.")

        # reading next packet...
        response_data = await reader.readexactly(resp_len)
        return response_data

    finally:
        writer.close()
        await writer.wait_closed()
