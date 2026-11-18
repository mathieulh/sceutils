#!/usr/bin/env python3
"""
pup_fiction.py - extract and decrypt a PS Vita update (PUP) - Python 3.

Only SPKG + SLSK (+ NPDRM) keys are needed in keys.py. Every other metadata
key is found in the modules decrypted along the way and saved to
<output>/derived_keys.py.

Usage: pup_fiction.py FILE.PUP output-dir/
"""
import binascii
import errno
import glob
import hashlib
import hmac
import os
import struct
import subprocess
import sys
from collections import defaultdict

from util import u32, u8, c_str, aes_cbc_decrypt, aes_ecb_decrypt
from scedecrypt import scedecrypt
from self2elf import self2elf
from scetypes import KeyType, SceType, SelfType
import keys

unarzl_exe = os.path.join(os.path.dirname(os.path.realpath(__file__)), "unarzl", "unarzl")
if not os.path.exists(unarzl_exe):
    print("Please cd to unarzl and type make")
    sys.exit(-1)

SCEUF_HEADER_SIZE = 0x80
SCEUF_FILEREC_SIZE = 0x20

pup_types = {
    0x100: "version.txt",
    0x101: "license.xml",
    0x200: "psp2swu.self",
    0x204: "cui_setupper.self",
    0x400: "package_scewm.wm",
    0x401: "package_sceas.as",
    0x2005: "UpdaterES1.CpUp",
    0x2006: "UpdaterES2.CpUp",
}

FSTYPE = [
    "unknown0",
    "os0",
    "unknown2",
    "unknown3",
    "vs0_chmod",
    "unknown5",
    "unknown6",
    "unknown7",
    "pervasive8",
    "boot_slb2",
    "vs0",
    "devkit_cp",
    "motionC",
    "bbmc",
    "unknownE",
    "motionF",
    "touch10",
    "touch11",
    "syscon12",
    "syscon13",
    "pervasive14",
    "unknown15",
    "vs0_tarpatch",
    "sa0",
    "pd0",
    "pervasive19",
    "unknown1A",
    "psp_emulist",
]

g_typecount = defaultdict(int)


# ------------------------------------------------------------------------------
# Runtime key discovery
#
# keys.py only holds the SPKG + SLSK (+ NPDRM) keys. All other metadata keys
# are looked up in already-decrypted modules ("key sources"):
#   second_loader.bin  -> BOOT     (kernel_boot_loader.self)
#   secure_kernel.bin  -> SECURE, SRVK (kprx_auth_sm.self, prog_rvk.srvk, sm)
#   kprx_auth_sm.elf   -> KERNEL, USER, APP
#
# A key is accepted only if it decrypts the target's metadata info block and
# both 16-byte padding fields come out as zero, then the metadata header is
# checked for sane values. Keys are stored as key[32] followed by iv[16]; if
# the adjacent IV doesn't validate, nearby 16-byte windows are tried.
# ------------------------------------------------------------------------------
SCE_HEADER_FMT = "<4sIBBHIQQ"
SCE_HEADER_SIZE = 0x20
META_INFO_SIZE = 0x40
FULL_RANGE = (0x00000000000, 0xFFFFFFFFFFFFFFFFFFFFFF)


def _enum(enum_cls, value):
    try:
        return enum_cls(value)
    except ValueError:
        raise KeyError("unknown {} value {}".format(enum_cls.__name__, value))


def _hexu(b):
    return binascii.hexlify(b).decode("ascii").upper()


class SceTarget(object):
    """Header data needed to find / validate the metadata key of an SCE file."""

    def __init__(self, data):
        if len(data) < SCE_HEADER_SIZE or data[0:4] != b"SCE\x00":
            raise ValueError("not an SCE file")
        (_magic, _ver, _plat, self.key_rev, self.sce_type, self.meta_offset,
         self.header_len, _dlen) = struct.unpack(SCE_HEADER_FMT, data[0:SCE_HEADER_SIZE])
        self.self_type = 0
        if self.sce_type == 1:  # SELF -> app info self_type
            appinfo_off = struct.unpack("<Q", data[0x38:0x40])[0]
            self.self_type = struct.unpack("<I", data[appinfo_off + 12:appinfo_off + 16])[0]
        base = self.meta_offset + 48
        self.meta_info = data[base:base + META_INFO_SIZE]
        self.meta_hdr = data[base + META_INFO_SIZE:self.header_len][0:32]
        if len(self.meta_info) != META_INFO_SIZE or len(self.meta_hdr) != 32:
            raise ValueError("truncated SCE header")
        c = self.meta_info
        self.c1, self.c2, self.c3, self.c4 = c[0:16], c[16:32], c[32:48], c[48:64]
        self.c24 = self.c2 + self.c4

    @property
    def slot(self):
        return (self.sce_type, self.self_type, self.key_rev)

    def quick_check(self, key):
        """IV-independent: blocks 2 and 4 of the metadata info are zero padding."""
        return aes_ecb_decrypt(key, self.c24) == self.c1 + self.c3

    def full_check(self, key, iv):
        if not self.quick_check(key):
            return False
        info = aes_cbc_decrypt(key, iv, self.meta_info)
        mh = aes_cbc_decrypt(info[0:16], info[32:48], self.meta_hdr)
        _siglen, _u1, sec_count, key_count, _opt, _u2, _u3 = struct.unpack("<QIIIIII", mh)
        return 0 < sec_count <= 0x100 and key_count <= 0x400


def read_sce_target(path):
    with open(path, "rb") as fin:
        data = fin.read(SCE_HEADER_SIZE)
        if len(data) < SCE_HEADER_SIZE or data[0:4] != b"SCE\x00":
            return None
        header_len = struct.unpack(SCE_HEADER_FMT, data)[6]
        if header_len > 0x100000:
            return None
        fin.seek(0)
        data = fin.read(header_len)
    try:
        return SceTarget(data)
    except (ValueError, struct.error):
        return None


class KeyResolver(object):
    def __init__(self, scan_step=4):
        self.sources = []                 # (name, bytes)
        self.found = defaultdict(list)    # slot -> [(key, iv, origin)]
        self.miss = {}                    # slot -> number of sources when last scan failed
        self.scan_step = scan_step
        self.spkg = [(binascii.unhexlify(k), binascii.unhexlify(i), label)
                     for k, i, label in keys.SPKG_KEYS]

    def add_source(self, path, name=None):
        if not os.path.exists(path):
            return False
        with open(path, "rb") as fin:
            self.sources.append((name or os.path.basename(path), fin.read()))
        return True

    def _scan(self, target):
        step = self.scan_step
        for name, buf in self.sources:
            for off in range(0, len(buf) - 48 + 1, step):
                key = buf[off:off + 32]
                if key.count(0) > 8 or not target.quick_check(key):
                    continue
                iv = buf[off + 32:off + 48]
                if target.full_check(key, iv):
                    return key, iv, "{}+0x{:X}".format(name, off)
                lo, hi = max(0, off - 0x200), min(len(buf) - 16, off + 0x200)
                for ivoff in range(lo - lo % 4, hi + 1, 4):
                    iv = buf[ivoff:ivoff + 16]
                    if target.full_check(key, iv):
                        return key, iv, "{}+0x{:X} (iv +0x{:X})".format(name, off, ivoff)
        return None

    def resolve(self, target):
        """Return (key, iv, origin) for the target, or None."""
        if target.sce_type == SceType.SPKG:  # fixed list from keys.py
            for key, iv, label in self.spkg:
                if target.full_check(key, iv):
                    return key, iv, "keys.py SPKG ({})".format(label)
            return None
        for entry in self.found[target.slot]:
            if target.full_check(entry[0], entry[1]):
                return entry
        if self.miss.get(target.slot) == len(self.sources):
            return None
        hit = self._scan(target)
        if hit is None:
            self.miss[target.slot] = len(self.sources)
            return None
        self.found[target.slot].append(hit)
        print("    [+] found {} {} keyrev {} key in {}".format(
            _enum(SceType, target.sce_type).name, _enum(SelfType, target.self_type).name,
            target.key_rev, hit[2]))
        return hit

    def activate(self, target, entry):
        """Make keys.SCE_KEYS return exactly this key for the target."""
        store = keys.SCE_KEYS
        store.clear()
        keys.register_npdrm_keys(store)
        store.register(KeyType.METADATA, _enum(SceType, target.sce_type), target.key_rev,
                       _hexu(entry[0]), _hexu(entry[1]), FULL_RANGE[0], FULL_RANGE[1],
                       _enum(SelfType, target.self_type))

    def prepare(self, path):
        """Resolve + activate the key for an SCE file. Returns origin or None."""
        target = read_sce_target(path)
        if target is None:
            return None
        entry = self.resolve(target)
        if entry is None:
            return None
        self.activate(target, entry)
        return entry[2]

    def write_derived(self, path):
        with open(path, "w") as fout:
            fout.write("# Keys discovered by pup_fiction.py (key[32] + iv[16] found in decrypted modules)\n")
            fout.write("from scetypes import *\n\nSCE_KEYS = KeyStore()\n")
            for slot in sorted(self.found):
                sce_type, self_type, rev = slot
                for key, iv, origin in self.found[slot]:
                    fout.write("\n# {}\nSCE_KEYS.register(\n".format(origin))
                    fout.write("    KeyType.METADATA,\n    SceType.{},\n    {},\n".format(
                        _enum(SceType, sce_type).name, rev))
                    fout.write("    '{}',\n    '{}',\n".format(_hexu(key), _hexu(iv)))
                    fout.write("    0x00000000000,\n    0xFFFFFFFFFFFFFFFFFFFFFF,\n    SelfType.{}\n)\n".format(
                        _enum(SelfType, self_type).name))


RESOLVER = KeyResolver()


def run_sce(path, action, label=None):
    """Find the key for `path`, then run `action()` (scedecrypt/self2elf call)."""
    label = label or os.path.basename(path)
    if RESOLVER.prepare(path) is None:
        print("[!] no key {}".format(label))
        return False
    try:
        action()
    except (KeyError, ValueError) as e:
        print("[!] Couldn't decrypt {}: {}".format(label, e.args[0] if e.args else e))
        return False
    return True


def sce_decrypt_file(path, dst, label=None):
    def go():
        with open(path, "rb") as fin:
            scedecrypt(fin, dst, silent=True)
    return run_sce(path, go, label)


def self2elf_file(path, out_path, label=None, **kw):
    def go():
        with open(path, "rb") as fin:
            with open(out_path, "wb") as fout:
                self2elf(fin, fout, silent=True, **kw)
    ok = run_sce(path, go, label)
    if not ok and os.path.exists(out_path) and os.path.getsize(out_path) == 0:
        os.remove(out_path)
    return ok


# ------------------------------------------------------------------------------
# PUP extraction
# ------------------------------------------------------------------------------
def make_filename(hdr, filetype):
    magic, version, flags, moffs, metaoffs = struct.unpack("<IIIIQ", hdr[0:24])
    if magic == 0x454353 and version == 3 and flags == 0x30040:
        meta = hdr[metaoffs:]
        t = u8(meta, 4)
        if t < 0x1C:
            name = "{}-{:02}.pkg".format(FSTYPE[t], g_typecount[t])
            g_typecount[t] += 1
            return name
    return "unknown-0x{:x}.pkg".format(filetype)


def pup_extract_files(pup, output):
    with open(pup, "rb") as fin:
        header = fin.read(SCEUF_HEADER_SIZE)
        if header[0:5] != b"SCEUF":
            print("Invalid PUP")
            return -1

        cnt = u32(header, 0x18)

        print("-" * 80)
        print("PUP Version: 0x{:x}".format(u32(header, 8)))
        print("Firmware Version: 0x{:08X}".format(u32(header, 0x10)))
        print("Build Number: {}".format(u32(header, 0x14)))
        print("Number of Files: {}".format(cnt))
        print("-" * 80)

        for x in range(cnt):
            fin.seek(SCEUF_HEADER_SIZE + x * SCEUF_FILEREC_SIZE)
            rec = fin.read(SCEUF_FILEREC_SIZE)
            filetype, offset, length, flags = struct.unpack("<QQQQ", rec)

            filename = pup_types.get(filetype)
            if not filename:
                fin.seek(offset)
                hdr = fin.read(0x1000)
                filename = make_filename(hdr, filetype)

            with open(os.path.join(output, filename), "wb") as fout:
                fin.seek(offset)
                fout.write(fin.read(length))
            print("- {}".format(filename))

        print("-" * 80)


def join_files(mask, output):
    files = sorted(glob.glob(mask))
    with open(output, "wb") as fout:
        for filename in files:
            with open(filename, "rb") as fin:
                fout.write(fin.read())
            os.remove(filename)


def pup_decrypt_packages(src, dst):
    files = sorted(os.path.basename(x) for x in glob.glob(os.path.join(src, "*.pkg")))

    for filename in files:
        if sce_decrypt_file(os.path.join(src, filename), dst, filename):
            print("Decrypted {}".format(filename))

    join_files(os.path.join(dst, "os0-*.pkg.seg02"), os.path.join(dst, "os0.bin"))
    join_files(os.path.join(dst, "vs0-*.pkg.seg02"), os.path.join(dst, "vs0.bin"))

    print("-" * 80)


def decrypt_updater_selfs(src, dst):
    # Needs USER/APP keys -> must run after kprx_auth_sm has been decrypted
    for filename in ["cui_setupper.self", "psp2swu.self"]:
        filepath = os.path.join(src, filename)
        if not os.path.exists(filepath):
            continue
        out_path = os.path.join(dst, filename.replace(".self", ".elf"))
        if self2elf_file(filepath, out_path, filename, ignore_sysver=True):
            print("Decrypted {}".format(filename))
    print("-" * 80)


def slb2_extract(src, dst):
    with open(src, "rb") as fin:
        hdr = fin.read(0x200)
        magic, version, flags, file_count, total_blocks = struct.unpack("<IIIII", hdr[0:20])
        if magic != 0x32424C53:
            raise RuntimeError("Invalid SLB2 file")
        print("SLB2 version: {}, flags: 0x{:X}, file_count: {}, total_blocks: 0x{:X}".format(
            version, flags, file_count, total_blocks))

        for x in range(file_count):
            entry_start = 0x20 + x * 0x30
            entry = hdr[entry_start:entry_start + 0x30]
            filename = c_str(entry[0x10:])

            block_offset, filesize = struct.unpack("<II", entry[0:8])

            with open(os.path.join(dst, filename), "wb") as fout:
                fin.seek(block_offset * 0x200)
                fout.write(fin.read(filesize))
                print("- {}".format(filename))

    print("-" * 80)


# ------------------------------------------------------------------------------
# SLSK (second_loader.enc / secure_kernel.enc) decryption
# Port of Proxima's slsk_tool.py / slsk_tool_type2.py.
# ------------------------------------------------------------------------------
SLSK_HEADER_FMT = "<IIIIIHHII"


class SlskError(RuntimeError):
    pass


def _hmac_sha256(key, data):
    return hmac.new(key, bytes(data), hashlib.sha256).digest()


def _slsk_check_header_sig(data, headersize, rsaver):
    warnings = []
    rsa_keys = keys.SLSK_RSA_KEYS
    modulus = rsa_keys[rsaver] if rsaver < len(rsa_keys) else rsa_keys[-1]
    sig = int.from_bytes(bytes(data[headersize - 0x100:headersize]), "little")
    dec = pow(sig, keys.SLSK_RSA_EXPONENT, modulus).to_bytes(0x100, "big")
    if dec[0:0xCE] != b"\x00\x01" + b"\xff" * 0xCB + b"\x00":
        warnings.append("invalid RSA signature padding")
        return warnings
    if dec[0xCE:0xE0] != keys.SLSK_RSA_STATIC:
        warnings.append("invalid RSA signature static data")
    if dec[0xE0:0x100] != _hmac_sha256(keys.SLSK_HMAC_KEY, data[:headersize - 0x100]):
        warnings.append("header HMAC mismatch")
    return warnings


def slsk_decrypt_data(data):
    """Returns (plaintext_body, info). Raises SlskError."""
    data = bytearray(data)
    if len(data) < 0x40:
        raise SlskError("file too small")
    (magic, headersize, versionsize, _revokesize, bodysize,
     encver, rsaver, _f1, _f2) = struct.unpack(SLSK_HEADER_FMT, bytes(data[0:0x20]))
    filehash = bytes(data[0x20:0x40])
    if magic != keys.SLSK_MAGIC:
        raise SlskError("invalid magic 0x{:08X}".format(magic))
    if headersize < 0x1E0 or headersize + bodysize > len(data) or bodysize % 0x10:
        raise SlskError("inconsistent sizes (header 0x{:X}, body 0x{:X}, file 0x{:X})".format(
            headersize, bodysize, len(data)))

    info = {"key_revision": encver, "version": None, "key_set": None, "warnings": []}
    if versionsize > 0:
        info["version"] = bytes(data[0x40:0x40 + versionsize]).decode("utf-8", "replace").rstrip("\x00")

    pck_key = getattr(keys, "SLSK_PCK_KEY", None)
    if pck_key:
        start, end = 0xD0 + versionsize, headersize + bodysize
        if isinstance(pck_key, str):
            pck_key = binascii.unhexlify(pck_key)
        data[start:end] = aes_cbc_decrypt(pck_key, keys.SLSK_PCK_IV, data[start:end])

    info["warnings"] += _slsk_check_header_sig(data, headersize, rsaver)

    enc_body = bytes(data[headersize:headersize + bodysize])
    body_hmac = _hmac_sha256(keys.SLSK_HMAC_KEY, enc_body)
    enc_bodykey = bytes(data[headersize - 0x1E0:headersize - 0x1C0])
    enc_hdrhmac = bytes(data[headersize - 0x120:headersize - 0x100])
    if encver >= len(keys.SLSK_KEY_IVS):
        raise SlskError("no key IV for key revision {}".format(encver))

    for set_name, masters in keys.SLSK_MASTER_KEYS:
        if encver >= len(masters):
            continue
        bodykey = aes_cbc_decrypt(masters[encver], keys.SLSK_KEY_IVS[encver], enc_bodykey)
        if aes_cbc_decrypt(bodykey, keys.SLSK_HDR_HMAC_IV, enc_hdrhmac) != body_hmac:
            continue
        body = aes_cbc_decrypt(bodykey[0:0x10], keys.SLSK_BODY_IV, enc_body)
        if hashlib.sha256(body).digest() != filehash:
            raise SlskError("key set {} matched body HMAC but plaintext SHA-256 differs".format(set_name))
        info["key_set"] = set_name
        return body, info

    enc_key = getattr(keys, "ENC_KEY", None)
    if enc_key:
        body = aes_cbc_decrypt(enc_key, getattr(keys, "ENC_IV", keys.SLSK_BODY_IV), enc_body)
        if hashlib.sha256(body).digest() == filehash:
            info["key_set"] = "legacy ENC_KEY"
            info["warnings"].append("decrypted with legacy ENC_KEY (no master key set matched)")
            return body, info

    raise SlskError("no SLSK master key set matches (key revision {})".format(encver))


def enc_decrypt(src, dst):
    with open(src, "rb") as fin:
        data = fin.read()
    body, info = slsk_decrypt_data(data)
    with open(dst, "wb") as fout:
        fout.write(body)
    return info


def slb2_decrypt(src, dst):
    # 1. SLSK: keys.py SLSK keys -> second_loader.bin / secure_kernel.bin
    for filename in ["second_loader.enc", "secure_kernel.enc"]:
        dst_filename = filename.replace(".enc", ".bin")
        try:
            info = enc_decrypt(os.path.join(src, filename), os.path.join(dst, dst_filename))
        except (SlskError, IOError) as e:
            print("[!] Couldn't decrypt {}: {}".format(filename, e))
            continue
        print("Decrypted {} to {} (key set {}, key rev {}{})".format(
            filename, dst_filename, info["key_set"], info["key_revision"],
            ", version {}".format(info["version"]) if info["version"] else ""))
        for w in info["warnings"]:
            print("    [!] {}".format(w))
        RESOLVER.add_source(os.path.join(dst, dst_filename))

    # 2. BOOT / SRVK keys come from second_loader / secure_kernel
    for filename in ["kernel_boot_loader.self", "prog_rvk.srvk"]:
        if sce_decrypt_file(os.path.join(src, filename), dst, filename):
            print("Decrypted {}".format(filename))

    # 3. SECURE key -> kprx_auth_sm, which holds the KERNEL/USER/APP keys
    for filename in ["kprx_auth_sm.self"]:
        dst_filename = filename.replace(".self", ".elf")
        out_path = os.path.join(dst, dst_filename)
        if self2elf_file(os.path.join(src, filename), out_path, filename):
            print("self2elf {}".format(filename))
            RESOLVER.add_source(out_path)

    nsbl_in = os.path.join(dst, "kernel_boot_loader.self.seg03")
    if os.path.exists(nsbl_in):
        print("unarzl nsbl.bin")
        subprocess.call([unarzl_exe, nsbl_in, os.path.join(dst, "nsbl.bin")])
    else:
        print("[!] kernel_boot_loader.self.seg03 not found, nsbl.bin not extracted")

    print("-" * 80)


# ------------------------------------------------------------------------------
# Filesystems
# ------------------------------------------------------------------------------
def extract_fs(output):
    fs_output = os.path.join(output, "fs")
    os.mkdir(fs_output)

    for partition in ["os0", "vs0"]:
        print("Extract {}".format(partition))
        partition_in = os.path.join(output, "PUP_dec", "{}.bin".format(partition))
        partition_out = os.path.join(fs_output, partition)
        os.mkdir(partition_out)
        subprocess.call(["7z", "x", partition_in, "-o{}".format(partition_out)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    vs0_tarpatch = os.path.join(output, "fs", "vs0_tarpatch")
    for filename in glob.glob(os.path.join(output, "PUP_dec", "vs0_tarpatch-*.pkg.seg02")):
        print("tarpatch {}".format(os.path.basename(filename)))
        subprocess.call(["7z", "x", filename, "-o{}".format(vs0_tarpatch)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("-" * 80)


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def decrypt_selfs(in_dir, out_dir, blacklist=None):
    if not blacklist:
        blacklist = []

    for root, dirs, files in os.walk(in_dir):
        for filename in files:
            name, ext = os.path.splitext(filename)
            if (ext in [".self", ".skprx", ".suprx"] or filename == "eboot.bin") and filename not in blacklist:
                relpath = os.path.relpath(root, in_dir)
                mkdir_p(os.path.join(out_dir, relpath))
                out_path = os.path.join(out_dir, relpath, "{}.elf".format(name))
                if self2elf_file(os.path.join(root, filename), out_path, filename):
                    print("self2elf {}".format(filename))


def decrypt_os0(output):
    os0_in = os.path.join(output, "fs", "os0")
    os0_out = os.path.join(output, "fs_dec", "os0")

    configs = ["psp2config_dolce.skprx", "psp2config_vita.skprx", "psp2config.skprx"]

    decrypt_selfs(os0_in, os0_out, configs)
    for filename in configs:
        in_path = os.path.join(os0_in, filename)
        if os.path.exists(in_path):
            print("Decrypt {}".format(filename))
            mkdir_p(os0_out)
            sce_decrypt_file(in_path, os0_out, filename)
    print("-" * 80)


def decrypt_vs0(output):
    for part in ["vs0", "vs0_tarpatch"]:
        vs0_in = os.path.join(output, "fs", part)
        vs0_out = os.path.join(output, "fs_dec", part)
        decrypt_selfs(vs0_in, vs0_out)
    print("-" * 80)


def extract_pup(pup, output):
    if os.path.exists(output):
        print("{} already exists, remove it first".format(output))
        return

    print("Extracting {} to {}".format(pup, output))

    os.mkdir(output)

    pup_dst = os.path.join(output, "PUP")
    os.mkdir(pup_dst)

    if pup_extract_files(pup, pup_dst) == -1:
        return

    pup_dec = os.path.join(output, "PUP_dec")
    os.mkdir(pup_dec)

    pup_decrypt_packages(pup_dst, pup_dec)

    slb2_dst = os.path.join(output, "SLB2")
    os.mkdir(slb2_dst)

    slb2_extract(os.path.join(pup_dec, "boot_slb2-00.pkg.seg02"), slb2_dst)

    slb2_dec = os.path.join(output, "SLB2_dec")
    os.mkdir(slb2_dec)
    slb2_decrypt(slb2_dst, slb2_dec)

    decrypt_updater_selfs(pup_dst, pup_dec)

    extract_fs(output)

    os.mkdir(os.path.join(output, "fs_dec"))
    decrypt_os0(output)
    decrypt_vs0(output)

    derived = os.path.join(output, "derived_keys.py")
    RESOLVER.write_derived(derived)
    print("Discovered {} key(s), saved to {}".format(
        sum(len(v) for v in RESOLVER.found.values()), derived))


def main():
    if len(sys.argv) != 3:
        print("Usage: ./pup_fiction.py FILE.PUP output-dir/")
        return 1
    extract_pup(sys.argv[1], sys.argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main())
