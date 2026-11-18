#!/usr/bin/env python3
"""
scedecrypt.py - decrypt SCE containers (SELF / SRVK / SPKG) into raw sections.

Python 3 rewrite of the sceutils scedecrypt module.

Output: one file per metadata section, named <input name>.segNN where NN is
the section's position in the metadata (same naming as sceutils, so
"boot_slb2-00.pkg.seg02" / "os0-NN.pkg.seg02" keep working).

Key selection: every key in keys.SCE_KEYS matching the file's SCE type, key
revision, self type and system version is tried, and the one that decrypts
the metadata info block (both 16-byte padding fields zero) is used. If none
match with the system version filter, the filter is dropped and all keys of
that type/revision are tried.

Usage: scedecrypt.py [-k KLICENSEE_HEX] [-v] input_file output_dir
"""
import argparse
import os
import sys
import zlib

from scetypes import (SceHeader, SelfHeader, AppInfoHeader, SrvkHeader, SpkgHeader,
                      MetadataInfo, MetadataHeader, MetadataSection, ControlInfoHeader,
                      SceType, SelfType, KeyType, EncryptionType, CompressionType)
from util import aes_cbc_decrypt, aes_ctr_decrypt


def _keystore(keystore):
    if keystore is not None:
        return keystore
    import keys
    return keys.SCE_KEYS


def read_all(inf):
    inf.seek(0)
    return inf.read()


def get_key_info(data, sce):
    """Return (sysver, self_type, extra_header) for an SCE file."""
    if sce.sce_type == SceType.SELF:
        self_hdr = SelfHeader(data, SceHeader.Size)
        appinfo = AppInfoHeader(data, self_hdr.appinfo_offset)
        return appinfo.sys_version, appinfo.self_type, (self_hdr, appinfo)
    if sce.sce_type == SceType.SRVK:
        if sce.header_length + SrvkHeader.Size <= len(data):
            srvk = SrvkHeader(data, sce.header_length)
            return srvk.sys_version, SelfType.NONE, srvk
        return -1, SelfType.NONE, None
    if sce.sce_type == SceType.SPKG:
        if sce.header_length + SpkgHeader.Size <= len(data):
            spkg = SpkgHeader(data, sce.header_length)
            # update_version is a 32-bit firmware number (0x0XYYZ000);
            # key ranges use the SELF sys_version format (<< 16)
            return spkg.update_version << 16, SelfType.NONE, spkg
        return -1, SelfType.NONE, None
    return -1, SelfType.NONE, None


def _npdrm_predecrypt(sce, enc_info, klictxt, keystore):
    keytype = 1 if sce.key_revision >= 2 else 0
    np_key, np_iv = keystore.get(KeyType.NPDRM, sce.sce_type, keyrev=keytype,
                                 selftype=SelfType.APP)
    klic = aes_cbc_decrypt(np_key, np_iv, klictxt)
    return aes_cbc_decrypt(klic, np_iv, enc_info)


def get_metadata(data, sce, sysver=-1, self_type=SelfType.NONE, klictxt=None,
                 keystore=None, silent=True):
    """
    Decrypt the metadata. Returns (MetadataHeader, [MetadataSection], [key16]).
    Raises KeyError if no registered key works.
    """
    keystore = _keystore(keystore)
    base = sce.metadata_offset + 48
    enc_info = data[base:base + MetadataInfo.Size]
    if klictxt is not None and self_type == SelfType.APP:
        enc_info = _npdrm_predecrypt(sce, enc_info, klictxt, keystore)

    candidates = keystore.get_all(KeyType.METADATA, sce.sce_type, sysver,
                                  sce.key_revision, self_type)
    if not candidates and sysver >= 0:
        candidates = keystore.get_all(KeyType.METADATA, sce.sce_type, -1,
                                      sce.key_revision, self_type)

    info = None
    for key, iv in candidates:
        test = MetadataInfo(aes_cbc_decrypt(key, iv, enc_info))
        if test.valid():
            info = test
            break
    if info is None:
        raise KeyError("No valid {} key for key revision {}, self type {}, sysver 0x{:X} "
                       "({} candidate(s) tried)".format(
                           getattr(sce.sce_type, "name", sce.sce_type), sce.key_revision,
                           getattr(self_type, "name", self_type), max(sysver, 0),
                           len(candidates)))

    enc_hdr = data[base + MetadataInfo.Size:sce.header_length]
    enc_hdr = enc_hdr[:len(enc_hdr) & ~0xF]
    dec = aes_cbc_decrypt(info.key, info.iv, enc_hdr)

    meta_hdr = MetadataHeader(dec, 0)
    off = MetadataHeader.Size
    sections = []
    for _ in range(meta_hdr.section_count):
        sections.append(MetadataSection(dec, off))
        off += MetadataSection.Size
    keys = [dec[off + i * 16:off + (i + 1) * 16] for i in range(meta_hdr.key_count)]

    if not silent:
        print(meta_hdr)
        for i, sec in enumerate(sections):
            print("Section {}:".format(i))
            print(sec)
    return meta_hdr, sections, keys


def section_data(data, section, keys, decompress=True):
    out = data[section.offset:section.offset + section.size]
    if section.encryption == EncryptionType.AES128CTR:
        out = aes_ctr_decrypt(keys[section.key_idx], keys[section.iv_idx], out)
    if decompress and section.compression == CompressionType.DEFLATE:
        out = zlib.decompressobj().decompress(out)
    return out


def scedecrypt(inf, outdir, decompress=True, silent=False, klictxt=None, keystore=None):
    data = read_all(inf)
    sce = SceHeader(data, 0)
    if not silent:
        print(sce)
    sysver, self_type, extra = get_key_info(data, sce)
    if not silent and extra is not None:
        for item in (extra if isinstance(extra, tuple) else (extra,)):
            print(item)
    _hdr, sections, keys = get_metadata(data, sce, sysver, self_type, klictxt, keystore, silent)

    basename = os.path.basename(inf.name)
    written = []
    for i, section in enumerate(sections):
        path = os.path.join(outdir, "{}.seg{:02}".format(basename, i))
        with open(path, "wb") as fout:
            fout.write(section_data(data, section, keys, decompress))
        written.append(path)
        if not silent:
            print("Wrote {}".format(path))
    return written


def get_control_info(data, self_hdr):
    """List of (ControlInfoHeader, payload bytes) of a SELF."""
    out = []
    off = self_hdr.controlinfo_offset
    end = off + self_hdr.controlinfo_length
    while off + ControlInfoHeader.Size <= end:
        ctrl = ControlInfoHeader(data, off)
        if ctrl.size == 0:
            break
        out.append((ctrl, data[off + ControlInfoHeader.Size:off + ctrl.size]))
        off += ctrl.size
        if not ctrl.more:
            break
    return out


def main():
    parser = argparse.ArgumentParser(description="Decrypt an SCE file into its sections")
    parser.add_argument("input")
    parser.add_argument("outdir")
    parser.add_argument("-k", "--klicensee", help="NPDRM klicensee (hex) for APP SELFs")
    parser.add_argument("-n", "--no-decompress", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    klic = bytes.fromhex(args.klicensee) if args.klicensee else None
    os.makedirs(args.outdir, exist_ok=True)
    with open(args.input, "rb") as fin:
        try:
            scedecrypt(fin, args.outdir, not args.no_decompress, not args.verbose, klic)
        except KeyError as e:
            print("[!] {}".format(e.args[0] if e.args else e))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
