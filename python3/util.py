"""
util.py - small helpers shared by the sceutils scripts (Python 3).

AES is provided by pycryptodome (`pip3 install pycryptodome`) if available,
otherwise by the `cryptography` package.
"""
import struct


def u8(buf, off):
    return buf[off]


def u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def c_str(buf):
    """NUL-terminated byte string -> str."""
    return bytes(buf).split(b"\x00", 1)[0].decode("ascii", "replace")


# ---------------------------------------------------------------------------
# AES backend
# ---------------------------------------------------------------------------
try:
    from Crypto.Cipher import AES as _AES  # pycryptodome

    def aes_cbc_decrypt(key, iv, data):
        return _AES.new(bytes(key), _AES.MODE_CBC, bytes(iv)).decrypt(bytes(data))

    def aes_ecb_decrypt(key, data):
        return _AES.new(bytes(key), _AES.MODE_ECB).decrypt(bytes(data))

    def aes_ctr_decrypt(key, iv, data):
        return _AES.new(bytes(key), _AES.MODE_CTR, nonce=b"",
                        initial_value=bytes(iv)).decrypt(bytes(data))

    AES_BACKEND = "pycryptodome"

except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _run(key, mode, data):
        d = Cipher(algorithms.AES(bytes(key)), mode).decryptor()
        return d.update(bytes(data)) + d.finalize()

    def aes_cbc_decrypt(key, iv, data):
        return _run(key, modes.CBC(bytes(iv)), data)

    def aes_ecb_decrypt(key, data):
        return _run(key, modes.ECB(), data)

    def aes_ctr_decrypt(key, iv, data):
        return _run(key, modes.CTR(bytes(iv)), data)

    AES_BACKEND = "cryptography"
