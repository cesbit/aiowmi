import functools
import os
import hashlib
import hmac
import math
import struct
from functools import reduce
from pyasn1.codec.der import decoder, encoder
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA1, MD5
from .rc4 import RC4
from .gss import gss_wrap_rc4


def _nfold(ba, nbytes):
    def rotate_right(ba, nbits):
        ba = bytearray(ba)
        n = len(ba)
        nbits %= (n * 8)
        # Rotate bytes
        for _ in range(nbits // 8):
            ba = bytearray([ba[-1]]) + ba[:-1]
        # Rotate remaining bits
        nbits %= 8
        if nbits > 0:
            last_bit = 0
            for i in range(len(ba)):
                new_last_bit = ba[i] & ((1 << nbits) - 1)
                ba[i] = (ba[i] >> nbits) | (last_bit << (8 - nbits))
                last_bit = new_last_bit
            ba[0] |= (last_bit << (8 - nbits))
        return ba

    def add_ones_complement(ba1, ba2):
        n = len(ba1)
        res = [0] * n
        carry = 0
        for i in range(n-1, -1, -1):
            s = ba1[i] + ba2[i] + carry
            res[i] = s & 0xff
            carry = s >> 8

        pos = n - 1
        while carry and pos >= 0:
            s = res[pos] + carry
            res[pos] = s & 0xff
            carry = s >> 8
            pos -= 1
        return bytearray(res)

    slen = len(ba)

    def lcm(a, b):
        return abs(a*b) // math.gcd(a, b)

    lcm_val = lcm(slen, nbytes)
    big_str = bytearray()
    curr = bytearray(ba)
    for i in range(lcm_val // slen):
        big_str += curr
        curr = rotate_right(curr, 13)

    parts = [big_str[i:i+nbytes] for i in range(0, len(big_str), nbytes)]
    return bytes(reduce(add_ones_complement, parts))


def derive_key(base_key, usage_int, payload_byte=None):
    constant = struct.pack('>I', usage_int)
    if payload_byte is not None:
        constant += bytes([payload_byte])

    nfolded = _nfold(constant, 16)
    cipher = Cipher(algorithms.AES(base_key), modes.ECB())
    encryptor1 = cipher.encryptor()
    b1 = encryptor1.update(nfolded) + encryptor1.finalize()
    encryptor2 = cipher.encryptor()
    b2 = encryptor2.update(b1) + encryptor2.finalize()

    return b1 + b2


def aes_cts_encrypt(key: bytes, plain: bytes) -> bytes:
    n = len(plain)  # 43 bytes
    iv = b'\x00' * 16
    pad_len = 16 - (n % 16)
    padded_plain = plain + b'\x00' * pad_len

    # CBC encryptie (correct IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    full_cipher = encryptor.update(padded_plain) + encryptor.finalize()

    c1 = full_cipher[0:16]
    c2 = full_cipher[16:32]
    c3 = full_cipher[32:48]

    return c1 + c3 + c2[:n % 16]


def decrypt_kerberos_aes_cts(key: bytes, usage: int, cipher: bytes) -> bytes:
    ciphertext = cipher[:-12]
    expected_hmac = cipher[-12:]

    ki = derive_key(key, usage, 0x55)
    ke = derive_key(key, usage, 0xAA)

    n = len(ciphertext)
    block_size = 16

    aes = AES.new(ke, AES.MODE_ECB)

    if n % block_size == 0:
        aes_cbc = AES.new(ke, AES.MODE_CBC, b'\x00' * block_size)
        plaintext_with_confounder = aes_cbc.decrypt(ciphertext)
    else:
        m = n // block_size
        last_blocks_len = n % block_size

        iv = b'\x00' * block_size
        plaintext_with_confounder = b''

        for i in range(m - 1):
            block = ciphertext[i*block_size: (i+1)*block_size]
            dec = aes.decrypt(block)
            plaintext_with_confounder += \
                bytes(a ^ b for a, b in zip(dec, iv))
            iv = block

        cn_minus_1 = ciphertext[(m-1)*block_size: m*block_size]
        cn = ciphertext[m*block_size:]

        dec_intermediate = aes.decrypt(cn_minus_1)

        pn = bytes(
            a ^ b for a, b in zip(dec_intermediate[:last_blocks_len], cn))

        stolen_bytes = dec_intermediate[last_blocks_len:]
        full_block_to_decrypt = cn + stolen_bytes

        dec_pn_minus_1 = aes.decrypt(full_block_to_decrypt)
        pn_minus_1 = bytes(a ^ b for a, b in zip(dec_pn_minus_1, iv))

        plaintext_with_confounder += pn_minus_1 + pn

    h = HMAC.new(ki, plaintext_with_confounder, SHA1)
    if h.digest()[:12] != expected_hmac:
        raise ValueError("Integrity check failed: HMAC mismatch")

    return plaintext_with_confounder


def encrypt_kerberos_aes_cts(session_key: bytes,
                             usage: int,
                             plain_text: bytes):
    ki = derive_key(session_key, usage, 0x55)
    ke = derive_key(session_key, usage, 0xAA)

    confounder = os.urandom(16)
    basic_plaintext = confounder + plain_text

    h = HMAC.new(ki, basic_plaintext, SHA1)
    checksum = h.digest()[:12]

    aes = AES.new(ke, AES.MODE_CBC, b'\x00' * 16)
    n = len(basic_plaintext)

    if n % 16 == 0:
        final_ctext = aes.encrypt(basic_plaintext)
    else:
        pad_len = 16 - (n % 16)
        padded_data = basic_plaintext + b'\x00' * pad_len
        ctext = aes.encrypt(padded_data)

        last_full_block = ctext[-32:-16]
        truncated_block = ctext[-16:]

        final_ctext = (
            ctext[:-32] +
            truncated_block +
            last_full_block[:16-pad_len]
        )

    return final_ctext + checksum


def encrypt_kerberos_rc4(session_key, usage, plaintext):
    confounder = os.urandom(8)
    data_to_encrypt = confounder + plaintext

    usage_bytes = struct.pack('<I', usage)
    k1 = HMAC.new(session_key, usage_bytes, MD5).digest()

    checksum = HMAC.new(k1, data_to_encrypt, MD5).digest()
    k3 = HMAC.new(k1, checksum, MD5).digest()

    cipher = RC4(k3)
    encrypted_data = cipher.encrypt(data_to_encrypt)

    return checksum + encrypted_data


def decrypt_kerberos_rc4(key, usage, data):
    checksum = data[:16]
    encrypted_data = data[16:]

    k1 = hmac.new(key, struct.pack('<I', usage), hashlib.md5).digest()
    k3 = hmac.new(k1, checksum, hashlib.md5).digest()

    cipher = RC4(k3)
    decrypted = cipher.decrypt(encrypted_data)

    return decrypted[8:]  # Skip 8 bytes confounder


def read_session_key(data: bytes) -> bytes:
    payload = data[16:]
    as_rep_part, _ = decoder.decode(payload)
    key_container_bytes = encoder.encode(as_rep_part[0])
    inner_key_seq, _ = decoder.decode(key_container_bytes)

    key_type_bytes = encoder.encode(inner_key_seq[0])
    key_value_bytes = encoder.encode(inner_key_seq[1])

    key_type_obj, _ = decoder.decode(key_type_bytes)
    key_value_obj, _ = decoder.decode(key_value_bytes)

    session_key = bytes(key_value_obj.asOctets())
    _key_type = int(key_type_obj)

    return session_key


#####################################################################
#
# All above is tested and working, below needs testing/work
#
#####################################################################


def aes_encrypt(key, data):
    # Basic AES-ECB encryption (building block for DK)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def derive_kerberos_keys(session_key, usage):
    """
    session_key: 16 or 32 bytes from ticket
    usage: Integer (example: 22 for Seal/Wrap, 24 for Sign/MIC)
    """
    # RFC 3961 constants (Labels)
    # Ke = DK(base_key, usage | 0xAA)
    # Ki = DK(base_key, usage | 0x55)

    label_enc = struct.pack('>IB', usage, 0xAA) + b'\x00' * 11
    label_int = struct.pack('>IB', usage, 0x55) + b'\x00' * 11

    # In Kerberos AES, 'constant' for DK label folded to blocksize (16 bytes).
    # For AES is the constant the label with padding.
    ke = aes_encrypt(session_key, label_enc.ljust(16, b'\x00'))
    ki = aes_encrypt(session_key, label_int.ljust(16, b'\x00'))
    return ke, ki


def kerberos_hmac_sha1_96(ki, data):
    """
    ki: Integrity Key (16 or 32 bytes)
    data: GSS header + (padded) payload
    """
    # Full HMAC-SHA1
    full_hmac = hmac.new(ki, data, hashlib.sha1).digest()

    # Shorten to the first 12 bytes (96-bit) (Kerberos AES)
    return full_hmac[:12]


def seal_func_kerberos(session_key: bytes):
    def _kerberos_sealer(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,    # sign+seal is a single stap
            message_to_encrypt: bytes,
            session_key: bytes) -> tuple[bytes, bytes]:
        return gss_wrap_rc4(session_key,
                            message_to_encrypt,
                            seq_num)
    return functools.partial(_kerberos_sealer, session_key=session_key)


def sign_func_kerberos(session_key):
    """
    Kerberos Signer (MIC) conform RFC 4121.
    """
    # Integrity Key (Ki) one time for session
    # Use 24 for MIC/Sign (Initiator)
    _, ki = derive_kerberos_keys(session_key, usage=24)

    def _kerberos_signer(flags, seq_num, message_to_sign):
        # GSS-API MIC Header (RFC 4121, Section 4.2.6.1)
        # 0404: Token ID for MIC
        # 00: Flags (0x00 for MIC from initiator)
        # ffffffffffff: Filler
        header = struct.pack('>HBB', 0x0404, 0x00, 0xff) + b'\xff' * 5

        # Add sequence number (8 bytes, Big-Endian)
        header += struct.pack('>Q', seq_num)

        # Calculate HMAC-SHA1-96 from Header + Message
        # (GSS_GetMIC)
        full_hmac = hmac.new(ki,
                             header + message_to_sign,
                             hashlib.sha1).digest()
        checksum = full_hmac[:12]  # Truncate to 96 bits

        # Return Header + Checksum
        # Used as 'auth_data' for RPC-packet
        return header + checksum

    return _kerberos_signer

