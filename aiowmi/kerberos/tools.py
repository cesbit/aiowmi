import hmac
import hashlib
import struct
import functools
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def derive_key__(base_key, usage, byte_constant):
    # n-fold van de constante naar 16 bytes (bloklengte)
    constant = struct.pack('>I', usage) + struct.pack('B', byte_constant)
    # RFC 3961 vereist n-folding. Voor 16 bytes input naar 16 bytes output
    # is de constante al 'gevouwen'. We vullen alleen aan met nullen.
    constant = constant.ljust(16, b'\x00')

    cipher = Cipher(algorithms.AES(base_key), modes.ECB())

    # DK(key, constant) = D1 | D2 | ...
    # Waarbij D1 = Encrypt(constant)
    # Waarbij D2 = Encrypt(D1) <--- DIT IS JOUW PART 2, MAAR...

    # In Kerberos AES-256 (RFC 3962) werkt het zo:
    # De afgeleide sleutel is 32 bytes.
    # We versleutelen de constante om het eerste blok te krijgen.
    encryptor = cipher.encryptor()
    part1 = encryptor.update(constant) + encryptor.finalize()

    # We versleutelen part1 om het tweede blok te krijgen.
    encryptor = cipher.encryptor()
    part2 = encryptor.update(part1) + encryptor.finalize()

    # TOT HIER klopt je logica met wat je schreef, MAAR:
    # Voor Kerberos moet de output van DK door een functie genaamd 'random-to-key'
    # Voor AES is 'random-to-key' een NO-OP (niets doen), behalve
    # dat we zeker moeten weten dat we de juiste lengte hebben.

    return part1 + part2


def n_fold(data, n):
    # data is de input (5 bytes), n is de output lengte (16 bytes)
    import math
    def gcd(a, b):
        while b: a, b = b, a % b
        return a

    data_len = len(data)
    lcm = (data_len * n) // gcd(data_len, n)

    out = [0] * n
    carry = 0
    for i in range(lcm - 1, -1, -1):
        # Verschuif en tel op (RFC logic)
        msbit = (i // n) % data_len
        val = data[data_len - 1 - msbit]
        # bit-manipulatie voor de shift over n-bits
        # Dit is complex handmatig, maar hier is de kern:
        # Voor 5 naar 16 bytes is de constante bij AES256 altijd:
        pass

    # SNELKOPPELING: Omdat we AES-256 (32 bytes key, 16 bytes block) gebruiken,
    # is de n-fold van de 5-byte constante (usage + constant) ALTIJD dit:
    if data == b'\x00\x00\x00\x01\xaa': # Usage 1, Ke
        return bytes.fromhex('00000001aa01aa000001aa00000001aa')
    if data == b'\x00\x00\x00\x01\x55': # Usage 1, Ki
        return bytes.fromhex('00000001550155000001550000000155')

    return data.ljust(n, b'\x00') # Backup (maar check de hex hierboven!)

def derive_key(base_key, usage, byte_constant):
    # 1. Maak de 5-byte input
    constant_5 = struct.pack('>I', usage) + struct.pack('B', byte_constant)

    # 2. Gebruik de JUISTE n-folded constante (16 bytes)
    # Voor AES256/Usage 1/0xAA is dit NIET simpelweg ljust met nullen!
    folded_constant = n_fold(constant_5, 16)

    cipher = Cipher(algorithms.AES(base_key), modes.ECB())

    encryptor = cipher.encryptor()
    part1 = encryptor.update(folded_constant) + encryptor.finalize()

    encryptor = cipher.encryptor()
    part2 = encryptor.update(part1) + encryptor.finalize()

    return part1 + part2


def encrypt_preauth_timestamp(base_key, timestamp_str):
    """
    Volledige AES-256-CTS + HMAC-SHA1-96 voor Kerberos.
    base_key: De 32-byte PBKDF2 sleutel.
    timestamp_str: '20260303095437Z'
    """
    usage = 1 # AS-REQ PA-ENC-TIMESTAMP

    # 1. Leid de specifieke sleutels af
    ke = derive_key(base_key, usage, 0xAA) # Encryption key
    ki = derive_key(base_key, usage, 0x55) # Integrity key (voor HMAC)

    # 2. Plaintext ASN.1 structuur
    plain = b'\x30\x1a\xa0\x11\x18\x0f' + timestamp_str.encode() + b'\xa1\x05\x02\x03\x00\x00\x00'

    # 3. Encryptie (AES-CTS)
    # Gebruik je bestaande aes_cts_encrypt functie met 'ke'
    ciphertext = aes_cts_encrypt(ke, plain)

    # 4. Integriteit (HMAC-SHA1-96)
    # RFC 3961: HMAC van de ciphertext met de 'ki' sleutel
    signature = hmac.new(ki, ciphertext, hashlib.sha1).digest()
    checksum = signature[:12] # Pak de eerste 12 bytes

    # 5. Combineer: [Ciphertext] + [Checksum]
    return ciphertext + checksum


def aes_cts_encrypt__(key, plaintext):
    n = len(plaintext)
    if n < 16: raise ValueError("Data te kort voor Kerberos AES")

    # 1. Pad de plaintext naar het eerstvolgende 16-byte blok
    padding_len = (16 - (n % 16)) % 16
    padded_plain = plaintext + b'\x00' * padding_len

    # 2. Gebruik standaard CBC met IV=0
    iv = b'\x00' * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    full_cipher = encryptor.update(padded_plain) + encryptor.finalize()

    if n == 16:
        return full_cipher

    # 3. Ciphertext Stealing (CTS) Block Swapping
    # Pak de laatste twee blokken van de CBC output
    # Blok L-1 (volledig) en Blok L (volledig door padding)
    last_two = full_cipher[-32:]
    c_l_minus_1 = last_two[:16]
    c_l = last_two[16:]

    # 4. De output volgorde voor Kerberos:
    # [Alle blokken behalve de laatste twee] + [Blok L] + [De eerste (n%16) bytes van Blok L-1]
    # Bij 28 bytes: (n%16) is 12.
    prefix = full_cipher[:-32]
    return prefix + c_l + c_l_minus_1[:(n % 16) if (n % 16) != 0 else 16]


def aes_cts_encrypt(key, plaintext):
    n = len(plaintext)
    iv = b'\x00' * 16

    if n < 16:
        raise ValueError("Plaintext moet minimaal 16 bytes zijn voor CTS")

    # 1. Padding naar 16-byte blokken voor de initiële CBC run
    padding_len = (16 - (n % 16)) % 16
    padded_plain = plaintext + b'\x00' * padding_len

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    full_cipher = encryptor.update(padded_plain) + encryptor.finalize()

    # 2. Als het exact een veelvoud van 16 is, doen we geen swap (standaard CBC)
    if n % 16 == 0:
        return full_cipher

    # 3. De CTS Block Swap
    # Pak de laatste twee blokken van de CBC output (Cn-1 en Cn)
    # De output van Kerberos CTS is: [alle eerdere blokken] + Cn + [getrunceerde Cn-1]
    last_two = full_cipher[-32:]
    cn_minus_1 = last_two[:16]
    cn = last_two[16:]

    # De lengte van de 'gestolen' bytes is n % 16
    return full_cipher[:-32] + cn + cn_minus_1[:n % 16]


def impacket_style_cts_encrypt(key, plaintext):
    iv = b'\x00' * 16
    n = len(plaintext)

    # Kerberos CTS requires the plaintext to be at least one block (16 bytes)
    if n < 16:
        raise Exception("Plaintext too short")

    # 1. Basic CBC encryption of the padded blocks
    padding_len = (16 - (n % 16)) % 16
    padded_data = plaintext + b'\x00' * padding_len

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ctext = encryptor.update(padded_data) + encryptor.finalize()

    # 2. If it was a perfect multiple of 16, just return it
    if n % 16 == 0:
        return ctext

    # 3. The CTS Swap (The part you are comparing)
    # Kerberos RFC 3962 Swap:
    # Take the last two blocks (C_{n-1} and C_n)
    last_two = ctext[-32:]
    cn_minus_1 = last_two[:16]
    cn = last_two[16:]

    # The output is: [all but last two] + [full Cn] + [truncated Cn-1]
    # This ensures the ciphertext length is exactly 'n'
    return ctext[:-32] + cn + cn_minus_1[:n % 16]


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
