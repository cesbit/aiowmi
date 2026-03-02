from .as_req import build_as_req, build_pa_enc, build_full_as_req
from .kdc import send_kerberos_packet
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def extract_kerberos_salt(error_data: bytes) -> str:
    """
    Extract salt from KRB-ERROR (0x7e) response.
    PA-ETYPE-INFO2 (Tag 19).
    """
    try:
        start_marker = b'\x1b\x1c'
        if start_marker in error_data:
            offset = error_data.find(start_marker) + 2
            salt = error_data[offset:offset+28].decode('utf-8')
            return salt
    except Exception:
        pass
    raise Exception('failed to get salt')




def nfold(data, n_bytes):
    # Een versimpelde n-fold voor de constante "kerberos" naar 16 bytes
    # Voor AES-256 resulteert 'kerberos' altijd in deze 16 bytes:
    return b'\x6b\x65\x72\x62\x65\x72\x6f\x73\x7b\x9b\x5b\x2b\x93\x13\x2b\x93'


def aes_string_to_key(password, salt):
    # Stap 1: PBKDF2 (De "seed" key)
    tkey = hashlib.pbkdf2_hmac('sha1', password.encode(), salt.encode(), 4096, 32)

    # Stap 2: Kerberos DK (Derive Key) met de constante "kerberos"
    # We gebruiken de tkey om de n-fold constante te versleutelen
    constant = nfold(b"kerberos", 16)

    # Gebruik AES-256 CBC met IV=0
    cipher = Cipher(algorithms.AES(tkey), modes.CBC(b'\x00' * 16))

    # Deel 1 van de definitieve sleutel
    encryptor1 = cipher.encryptor()
    part1 = encryptor1.update(constant) + encryptor1.finalize()

    # Deel 2 van de definitieve sleutel (met part1 als nieuwe input)
    encryptor2 = cipher.encryptor()
    part2 = encryptor2.update(part1) + encryptor2.finalize()

    return part1 + part2


async def get_tgt(username: str, password: str, domain: str,
                  kdc_host: str, kdc_port: int = 88):
    as_req = build_as_req(username, domain)
    #  Package AS_REQ from impacket (this one we know works)
    #  b'j\x81\xcb0\x81\xc8\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\n\xa3\x150\x130\x11\xa1\x04\x02\x02\x00\x80\xa2\t\x04\x070\x05\xa0\x03\x01\x01\xff\xa4\x81\xa40\x81\xa1\xa0\x07\x03\x05\x00P\x80\x00\x00\xa1\x1a0\x18\xa0\x03\x02\x01\x01\xa1\x110\x0f\x1b\radministrator\xa2\x18\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa3+0)\xa0\x03\x02\x01\x01\xa1"0 \x1b\x06krbtgt\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa5\x11\x18\x0f20260228135352Z\xa6\x11\x18\x0f20260228135352Z\xa7\x06\x02\x04\x17=\xf9\xc3\xa8\x050\x03\x02\x01\x12'

    #  Package AS_REQ from my lib (not tested yet)
    #  b'j\x81\xca\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\n\xa3\x170\x150\x130\x11\xa1\x04\x02\x02\x00\x80\xa2\t\x04\x070\x05\xa0\x03\x01\x01\xff\xa4\x81\xa40\x81\xa1\xa0\x07\x03\x05\x00@\x81\x00\x10\xa1\x1a0\x18\xa0\x03\x02\x01\x01\xa1\x110\x0f\x1b\radministrator\xa2\x18\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa3+0)\xa0\x03\x02\x01\x01\xa1"0 \x1b\x06krbtgt\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa5\x11\x18\x0f20260228141544Z\xa6\x11\x18\x0f20260228141544Z\xa7\x06\x02\x04{\xc0\xff\x98\xa8\x050\x03\x02\x01\x12'
    resp = await send_kerberos_packet(as_req, kdc_host, kdc_port)
    # resp = b'~\x81\xce0\x81\xcb\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x1e\xa4\x11\x18\x0f20260302101520Z\xa5\x05\x02\x03\x0b\x85\xd0\xa6\x03\x02\x01\x19\xa9\x18\x1b\x16LAB.TEST-TECHNOLOGY.NL\xaa+0)\xa0\x03\x02\x01\x01\xa1"0 \x1b\x06krbtgt\x1b\x16LAB.TEST-TECHNOLOGY.NL\xacY\x04W0U02\xa1\x03\x02\x01\x13\xa2+\x04)0\'0%\xa0\x03\x02\x01\x12\xa1\x1e\x1b\x1cWIN-RNHRHNNBVI8Administrator0\t\xa1\x03\x02\x01\x02\xa2\x02\x04\x000\t\xa1\x03\x02\x01\x10\xa2\x02\x04\x000\t\xa1\x03\x02\x01\x0f\xa2\x02\x04\x00'
    print(f'Response: {resp}')
    salt = extract_kerberos_salt(resp)
    # salt = 'LAB.TEST-TECHNOLOGY.NLAdministrator'
    print(f'Salt: {salt}')
    print(f'Password: {password}')
    key = aes_string_to_key(password, salt)
    print(f'Key: {key}')
    # My key:    b'\xd5\x10Y\x03\x143\x89g\xba\x84\x9b\x01\x9az\x03\xa4\xa7\xfa\x0fe\xcb\x1a\x0c\xca\xc0q\x00\xc6%\xa6\xceT'
    # Impacket:  b'\xd5\x10Y\x03\x143\x89g\xba\x84\x9b\x01\x9az\x03\xa4\xa7\xfa\x0fe\xcb\x1a\x0c\xca\xc0q\x00\xc6%\xa6\xceT'

    #
    # assert (0)
    # final_as_req = get_final_as_req_packet(username, domain.upper(), password, salt)
    # pa_enc = build_pa_enc(key)
    # print(f'PA_ENC (HEX): {pa_enc.hex()}')
    # # assert 0

    # final_as_req = build_as_req(username, domain, pa_enc)
    # print(f'final_as_req (HEX): {final_as_req.hex()}')
    # #  Packege from impacket (we know it works)
    # #  b'j\x82\x01\x190\x82\x01\x15\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\n\xa3b0`0K\xa1\x03\x02\x01\x02\xa2D\x04B0@\xa0\x03\x02\x01\x12\xa29\x047\x81T\x99\xb6\xe8\x8c3\'\xff\xbbbd\\M\x02I\x1c~\xdd\xc2\xc5\xbb\x02\x88\x9b\x9e;\xb6T\x058\xd9^\xcd%<\xa1t\x08-f\x00\xe3\x8c\xcf\xc5\xf8\xab\x87nP\xb3j\xb6J0\x11\xa1\x04\x02\x02\x00\x80\xa2\t\x04\x070\x05\xa0\x03\x01\x01\xff\xa4\x81\xa40\x81\xa1\xa0\x07\x03\x05\x00P\x80\x00\x00\xa1\x1a0\x18\xa0\x03\x02\x01\x01\xa1\x110\x0f\x1b\radministrator\xa2\x18\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa3+0)\xa0\x03\x02\x01\x01\xa1"0 \x1b\x06krbtgt\x1b\x16LAB.TEST-TECHNOLOGY.NL\xa5\x11\x18\x0f20260303101248Z\xa6\x11\x18\x0f20260303101248Z\xa7\x06\x02\x04L\r5-\xa8\x050\x03\x02\x01\x12'
    # #
    # #  Package (final_packet) from my lib (HEX)
    # #  6a81f43081f1a103020105a20302010aa351304f303aa103020102a2330431302fa003020112a2280426d2ceeba1f7d8792a06f81a3f74ca9c6d3e0d319b9497e2213dca37f549fa376a8108d1cc74463011a10402020080a20904073005a0030101ffa4819130818ea00703050050800000a11a3018a003020101a111300f1b0d61646d696e6973747261746f72a2181b164c41422e544553542d544543484e4f4c4f47592e4e4ca32b3029a003020101a12230201b066b72627467741b164c41422e544553542d544543484e4f4c4f47592e4e4ca511180f32303236303330333132353230335aa7060204007677d8a8053003020112


    pck = build_full_as_req(username, domain, key)
    print(pck.hex())

    resp = await send_kerberos_packet(pck, kdc_host, kdc_port)
    print(f'Response: {resp}')
    assert 0