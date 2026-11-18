#!/usr/bin/env python3
"""
self2elf.py - convert a SELF into a plain ELF (Python 3).

Python 3 rewrite of the sceutils self2elf module. The ELF header and
program headers are copied from the SELF (section headers are dropped);
every SEGMENT section is decrypted/decompressed and written at its
program header's p_offset.

Usage: self2elf.py [-k KLICENSEE_HEX] [-s] [-v] input.self output.elf
"""
import argparse
import sys

from scetypes import (SceHeader, SelfHeader, AppInfoHeader, ElfHeader, ElfPhdr,
                      SceType, SectionType)
from scedecrypt import read_all, get_metadata, section_data, get_control_info


def self2elf(inf, outf, klictxt=None, silent=False, ignore_sysver=False, keystore=None):
    data = read_all(inf)
    sce = SceHeader(data, 0)
    if sce.sce_type != SceType.SELF:
        raise ValueError("Not a SELF file (type {})".format(sce.sce_type))
    self_hdr = SelfHeader(data, SceHeader.Size)
    appinfo = AppInfoHeader(data, self_hdr.appinfo_offset)
    elf_hdr = ElfHeader(data, self_hdr.elf_offset)

    phdrs = [ElfPhdr(data, self_hdr.phdr_offset + i * ElfPhdr.Size)
             for i in range(elf_hdr.e_phnum)]

    if not silent:
        print(sce)
        print(self_hdr)
        print(appinfo)
        print(elf_hdr)
        for ctrl, _payload in get_control_info(data, self_hdr):
            print("Control info: {} (0x{:X} bytes)".format(
                getattr(ctrl.type, "name", ctrl.type), ctrl.size))

    sysver = -1 if ignore_sysver else appinfo.sys_version
    _meta, sections, keys = get_metadata(data, sce, sysver, appinfo.self_type, klictxt,
                                         keystore, silent)

    # Section headers are not carried in usable form by the SELF: drop them
    elf_hdr.e_shoff = 0
    elf_hdr.e_shnum = 0
    elf_hdr.e_shstrndx = 0

    out = bytearray()

    def put(offset, blob):
        end = offset + len(blob)
        if len(out) < end:
            out.extend(b"\x00" * (end - len(out)))
        out[offset:end] = blob

    put(0, elf_hdr.pack())
    for i, phdr in enumerate(phdrs):
        put(elf_hdr.e_phoff + i * elf_hdr.e_phentsize, phdr.pack())

    for section in sections:
        if section.type != SectionType.SEGMENT or section.seg_idx >= len(phdrs):
            continue
        blob = section_data(data, section, keys, decompress=True)
        phdr = phdrs[section.seg_idx]
        if len(blob) != phdr.p_filesz and not silent:
            print("[!] segment {}: size 0x{:X} != p_filesz 0x{:X}".format(
                section.seg_idx, len(blob), phdr.p_filesz))
        put(phdr.p_offset, blob)

    outf.write(bytes(out))
    return len(out)


def main():
    parser = argparse.ArgumentParser(description="Convert a SELF to an ELF")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("-k", "--klicensee", help="NPDRM klicensee (hex) for APP SELFs")
    parser.add_argument("-s", "--ignore-sysver", action="store_true",
                        help="don't filter keys by system version")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    klic = bytes.fromhex(args.klicensee) if args.klicensee else None
    with open(args.input, "rb") as fin:
        try:
            data_len = 0
            with open(args.output, "wb") as fout:
                data_len = self2elf(fin, fout, klic, not args.verbose, args.ignore_sysver)
        except KeyError as e:
            print("[!] {}".format(e.args[0] if e.args else e))
            return 1
    if args.verbose:
        print("Wrote {} (0x{:X} bytes)".format(args.output, data_len))
    return 0


if __name__ == "__main__":
    sys.exit(main())
