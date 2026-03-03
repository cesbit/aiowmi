import functools
import hashlib
import hmac
import math
import struct
from functools import reduce
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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
    """
    seal_func for Kerberos.
    session_key: Raw key from ticket
    """
    # Prepare: keys for one time per session
    # Use 22 for Seal/Wrap (Initiator)
    ke, ki = derive_kerberos_keys(session_key, usage=22)

    def _kerberos_sealer(
            flags: int,
            seq_num: int,
            message_to_sign: bytes,    # sign+seal is a single stap
            message_to_encrypt: bytes,
            ke: bytes,
            ki: bytes) -> tuple[bytes, bytes]:

        # Padding (AES block size 16)
        pad_len = 16 - (len(message_to_encrypt) % 16)
        padded_data = message_to_encrypt + (b'\x00' * pad_len)

        # GSS-API Header (RFC 4121) for Wrap
        # 0504 = Wrap Token, 06 = Flags (Sealed + Acceptor Subkey)
        header = struct.pack('>HHBB', 0x0504, 0x0600, 0x00, 0x00)
        header += struct.pack('>Q', seq_num)

        # Encryption with AES-CTS (Ke)
        ciphertext = aes_cts_encrypt(ke, padded_data)

        # Checksum (MIC) (Header + Padded Plaintext (Ki))
        # Important: checksum for plaintext data
        checksum = kerberos_hmac_sha1_96(ki, header + padded_data)

        # Return (Sealed data, Auth Verifier)
        # Auth Verifier is the GSS Header + Checksum
        return ciphertext, header + checksum

    return functools.partial(_kerberos_sealer, ke=ke, ki=ki)


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
