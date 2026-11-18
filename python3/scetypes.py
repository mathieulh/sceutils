"""
scetypes.py - SCE container structures and key store (Python 3).

Python 3 rewrite of the sceutils scetypes module, keeping the same public
names (SceType, SelfType, KeyType, KeyStore, SceHeader, SelfHeader, ...)
so keys.py and other sceutils-style scripts keep working.
"""
import binascii
import struct
from collections import defaultdict
from enum import IntEnum


class SceType(IntEnum):
    SELF = 1
    SRVK = 2
    SPKG = 3
    DEV = 0xC0


class SelfType(IntEnum):
    NONE = 0
    KERNEL = 0x07
    APP = 0x08
    BOOT = 0x09
    SECURE = 0x0B
    USER = 0x0D


class KeyType(IntEnum):
    METADATA = 0
    NPDRM = 1


class SelfPlatform(IntEnum):
    PS3 = 0
    VITA = 0x40


class SectionType(IntEnum):
    PLAIN = 1          # header-like data (SPKG / SRVK header ...)
    SEGMENT = 2        # ELF program segment / payload
    DATA = 3           # SPKG payload


class EncryptionType(IntEnum):
    NONE = 1
    AES128CTR = 3


class HashType(IntEnum):
    NONE = 1
    HMACSHA1 = 2
    HMACSHA256 = 6


class CompressionType(IntEnum):
    NONE = 1
    DEFLATE = 2


class ControlType(IntEnum):
    CONTROL_FLAGS = 1
    DIGEST_SHA1 = 2
    NPDRM_PS3 = 3
    DIGEST_SHA256 = 4
    NPDRM_VITA = 5
    UNK_SIG1 = 6
    UNK_HASH1 = 7


def _enum(cls, value):
    try:
        return cls(value)
    except ValueError:
        return value


# ---------------------------------------------------------------------------
# Key store
# ---------------------------------------------------------------------------
class KeyEntry(object):
    def __init__(self, keyrev, key, iv, minver, maxver, selftype):
        self.keyrev = keyrev
        self.key = binascii.a2b_hex(key) if isinstance(key, str) else bytes(key)
        self.iv = binascii.a2b_hex(iv) if isinstance(iv, str) else bytes(iv)
        self.minver = minver
        self.maxver = maxver
        self.selftype = selftype

    def matches(self, sysver, keyrev, selftype):
        if sysver >= 0 and not (self.minver <= sysver <= self.maxver):
            return False
        if keyrev >= 0 and keyrev != self.keyrev:
            return False
        if selftype != SelfType.NONE and selftype != self.selftype:
            return False
        return True


class KeyStore(object):
    def __init__(self):
        self._store = defaultdict(lambda: defaultdict(list))

    def clear(self):
        self._store.clear()

    def register(self, keytype, sce_type, keyrev, key, iv,
                 minver=0, maxver=0xFFFFFFFFFFFFFFFFFFFFFF, selftype=SelfType.NONE):
        self._store[keytype][sce_type].append(
            KeyEntry(keyrev, key, iv, minver, maxver, selftype))

    def get_all(self, keytype, sce_type, sysver=-1, keyrev=-1, selftype=SelfType.NONE):
        """All (key, iv) pairs matching the filters, in registration order."""
        return [(e.key, e.iv) for e in self._store[keytype][sce_type]
                if e.matches(sysver, keyrev, selftype)]

    def get(self, keytype, sce_type, sysver=-1, keyrev=-1, selftype=SelfType.NONE):
        found = self.get_all(keytype, sce_type, sysver, keyrev, selftype)
        if not found:
            raise KeyError("Cannot find key/iv for {} {} sysver 0x{:X} keyrev {} {}".format(
                _name(keytype), _name(sce_type), sysver if sysver >= 0 else 0, keyrev, _name(selftype)))
        return found[0]

    def __str__(self):
        lines = []
        for keytype, by_type in self._store.items():
            for sce_type, entries in by_type.items():
                for e in entries:
                    lines.append("{} {} rev {} {} [0x{:X}-0x{:X}] {}".format(
                        _name(keytype), _name(sce_type), e.keyrev, _name(e.selftype),
                        e.minver, e.maxver, binascii.hexlify(e.key).decode().upper()))
        return "\n".join(lines)


def _name(v):
    return getattr(v, "name", str(v))


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------
class _Struct(object):
    FMT = ""
    FIELDS = ()
    Size = 0

    def __init__(self, data, offset=0):
        values = struct.unpack_from(self.FMT, data, offset)
        for name, value in zip(self.FIELDS, values):
            setattr(self, name, value)

    def pack(self):
        return struct.pack(self.FMT, *[getattr(self, f) for f in self.FIELDS])

    def __str__(self):
        out = [self.__class__.__name__ + ":"]
        for f in self.FIELDS:
            v = getattr(self, f)
            if isinstance(v, bytes):
                v = binascii.hexlify(v).decode().upper()
            elif isinstance(v, IntEnum):
                v = v.name
            elif isinstance(v, int):
                v = "0x{:X}".format(v)
            out.append("  {:<22} {}".format(f, v))
        return "\n".join(out)


class SceHeader(_Struct):
    FMT = "<4sIBBHIQQ"
    FIELDS = ("magic", "version", "platform", "key_revision", "sce_type",
              "metadata_offset", "header_length", "data_length")
    Size = 0x20

    def __init__(self, data, offset=0):
        super(SceHeader, self).__init__(data, offset)
        if self.magic != b"SCE\x00":
            raise ValueError("Invalid SCE magic")
        if self.version != 3:
            raise ValueError("Unsupported SCE version {}".format(self.version))
        self.platform = _enum(SelfPlatform, self.platform)
        self.sce_type = _enum(SceType, self.sce_type)


class SelfHeader(_Struct):
    FMT = "<11Q"
    FIELDS = ("file_length", "field_8", "self_offset", "appinfo_offset", "elf_offset",
              "phdr_offset", "shdr_offset", "segment_info_offset", "sceversion_offset",
              "controlinfo_offset", "controlinfo_length")
    Size = 0x58


class AppInfoHeader(_Struct):
    FMT = "<QIIQQ"
    FIELDS = ("authid", "vendor_id", "self_type", "sys_version", "field_18")
    Size = 0x20

    def __init__(self, data, offset=0):
        super(AppInfoHeader, self).__init__(data, offset)
        self.self_type = _enum(SelfType, self.self_type)


class ElfHeader(_Struct):
    FMT = "<16sHHIIIIIHHHHHH"
    FIELDS = ("e_ident", "e_type", "e_machine", "e_version", "e_entry", "e_phoff",
              "e_shoff", "e_flags", "e_ehsize", "e_phentsize", "e_phnum",
              "e_shentsize", "e_shnum", "e_shstrndx")
    Size = 0x34

    def __init__(self, data, offset=0):
        super(ElfHeader, self).__init__(data, offset)
        if self.e_ident[0:4] != b"\x7fELF":
            raise ValueError("Invalid ELF header")


class ElfPhdr(_Struct):
    FMT = "<8I"
    FIELDS = ("p_type", "p_offset", "p_vaddr", "p_paddr", "p_filesz", "p_memsz",
              "p_flags", "p_align")
    Size = 0x20


class SegmentInfo(_Struct):
    FMT = "<QQIIII"
    FIELDS = ("offset", "size", "compressed", "field_14", "plaintext", "field_1C")
    Size = 0x20


class MetadataInfo(_Struct):
    FMT = "<16s16s16s16s"
    FIELDS = ("key", "key_pad", "iv", "iv_pad")
    Size = 0x40

    def valid(self):
        return self.key_pad == b"\x00" * 16 and self.iv_pad == b"\x00" * 16


class MetadataHeader(_Struct):
    FMT = "<QIIIIII"
    FIELDS = ("signature_input_length", "field_8", "section_count", "key_count",
              "opt_header_size", "field_18", "field_1C")
    Size = 0x20


class MetadataSection(_Struct):
    FMT = "<QQIIIIIIII"
    FIELDS = ("offset", "size", "type", "seg_idx", "hashtype", "hash_idx",
              "encryption", "key_idx", "iv_idx", "compression")
    Size = 0x30

    def __init__(self, data, offset=0):
        super(MetadataSection, self).__init__(data, offset)
        self.type = _enum(SectionType, self.type)
        self.hashtype = _enum(HashType, self.hashtype)
        self.encryption = _enum(EncryptionType, self.encryption)
        self.compression = _enum(CompressionType, self.compression)


class SrvkHeader(_Struct):
    FMT = "<IIQ"
    FIELDS = ("field_0", "field_4", "sys_version")
    Size = 0x10


class SpkgHeader(_Struct):
    FMT = "<IIIIQQQ"
    FIELDS = ("field_0", "pkg_type", "flags", "field_C", "update_version",
              "final_size", "decrypted_size")
    Size = 0x28


class ControlInfoHeader(_Struct):
    FMT = "<IIQ"
    FIELDS = ("type", "size", "more")
    Size = 0x10

    def __init__(self, data, offset=0):
        super(ControlInfoHeader, self).__init__(data, offset)
        self.type = _enum(ControlType, self.type)
