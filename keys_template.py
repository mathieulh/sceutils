# ============================================================================
# keys.py - key file template for pup_fiction.py (Python 2 and 3)
#
# This file ships WITHOUT any key material. Copy it to keys.py and fill in
# the empty strings ('') with hex values. Do not commit your filled keys.py
# (add it to .gitignore).
#
# Only root keys are needed:
#   * SPKG metadata keys  -> decrypt the PUP packages (incl. boot_slb2)
#   * SLSK keys           -> decrypt second_loader.enc / secure_kernel.enc
#   * NPDRM keys          -> optional, only for NPDRM (klicensee) APP SELFs
#
# Every other metadata key (BOOT, SECURE, SRVK, KERNEL, USER, APP) is
# discovered at runtime by pup_fiction.py from the decrypted modules and
# written to <output>/derived_keys.py.
#
# Missing or malformed entries are skipped (a summary is printed to stderr
# on import), so a partially filled file still runs: the parts that need a
# missing key are reported as "no key" / "Couldn't decrypt".
# ============================================================================
from scetypes import *
import binascii
import sys

_missing = []


def _h(value, size, name):
    """Hex string -> bytes. Blank -> None. Wrong length/format -> None + warning."""
    value = (value or '').replace(' ', '').strip()
    if not value:
        return None
    try:
        raw = binascii.unhexlify(value)
    except (TypeError, ValueError, binascii.Error):
        sys.stderr.write('[keys.py] {}: not a valid hex string, ignored\n'.format(name))
        return None
    if size and len(raw) != size:
        sys.stderr.write('[keys.py] {}: expected {} bytes, got {}, ignored\n'.format(name, size, len(raw)))
        return None
    return raw


def _prefix(values, size, name):
    """Convert a revision-indexed list; stops at the first missing entry so
    indexes keep matching the header's key revision."""
    out = []
    for i, v in enumerate(values):
        raw = _h(v, size, '{}[{}]'.format(name, i))
        if raw is None:
            break
        out.append(raw)
    return out


# ----------------------------------------------------------------------------
# SPKG metadata keys: (key 32 bytes, iv 16 bytes, label)
# Every entry is tried against each package; the one that decrypts it is used.
# ----------------------------------------------------------------------------
SPKG_KEYS = [
    ('', '', 'retail'),
    ('', '', 'internal'),
    ('', '', 'prototype'),
]

# ----------------------------------------------------------------------------
# NPDRM keys: (key type, key 16 bytes, iv 16 bytes) - optional
# ----------------------------------------------------------------------------
NPDRM_KEYS = [
    (0, '', '00000000000000000000000000000000'),
    (1, '', '00000000000000000000000000000000'),
]

# ----------------------------------------------------------------------------
# SLSK (second_loader.enc / secure_kernel.enc)
# Format from Proxima's PSVita Second Loader/Secure Kernel Tool.
# ----------------------------------------------------------------------------
SLSK_MAGIC = 0x64B2C8E5          # file magic, not a key

# Master keys (32 bytes each), indexed by the header "Encryption Key
# Revision". Each set is tried in order; the one whose body HMAC matches
# is used.
_SLSK_MASTER_KEYS = [
    ('type2', ['', '', '', '', '', '']),
    ('type3', ['', '', '', '', '', '']),
]

# IVs used to decrypt the body key (16 bytes), indexed by key revision
_SLSK_KEY_IVS = ['', '', '', '', '', '']

# IVs used for the auxiliary keys (16 bytes) - informational, unused
_SLSK_AUX_IVS = ['', '', '', '', '']

_SLSK_BODY_IV     = ''           # 16 bytes
_SLSK_HDR_HMAC_IV = ''           # 16 bytes
_SLSK_HMAC_KEY    = ''           # 32 bytes

# Optional key 8 PCK layer (key 16/24/32 bytes, iv 16 bytes)
_SLSK_PCK_KEY = ''
_SLSK_PCK_IV  = ''

# RSA-2048 public moduli (Python ints, e.g. 0xBCDA...), indexed by the
# header "RSA Key Revision". Only used for the (non-fatal) header signature
# check; if empty, the check just reports "invalid RSA signature padding".
_SLSK_RSA_KEYS = [
]

# Standard values, not secrets
SLSK_RSA_EXPONENT = 0x10001
SLSK_RSA_STATIC = binascii.unhexlify('3030300C06082A864886F70D020905000420')  # DigestInfo prefix

# ----------------------------------------------------------------------------
# Legacy fixed SLSK body key (optional, last-resort fallback; only accepted
# if the SHA-256 of the decrypted body matches)
# ----------------------------------------------------------------------------
_ENC_KEY = ''                    # 16 bytes
_ENC_IV  = ''                    # 16 bytes


# ============================================================================
# Nothing to edit below this line
# ============================================================================
SPKG_KEYS = [(k, i, label) for k, i, label in SPKG_KEYS
             if _h(k, 32, 'SPKG ' + label) and _h(i, 16, 'SPKG {} iv'.format(label))]
if not SPKG_KEYS:
    _missing.append('SPKG keys (nothing can be decrypted)')

NPDRM_KEYS = [(rev, k, i) for rev, k, i in NPDRM_KEYS
              if _h(k, 16, 'NPDRM {}'.format(rev)) and _h(i, 16, 'NPDRM {} iv'.format(rev))]

SLSK_MASTER_KEYS = [(name, _prefix(ks, 32, 'SLSK master ' + name)) for name, ks in _SLSK_MASTER_KEYS]
SLSK_MASTER_KEYS = [(name, ks) for name, ks in SLSK_MASTER_KEYS if ks]
SLSK_KEY_IVS = _prefix(_SLSK_KEY_IVS, 16, 'SLSK key IV')
SLSK_AUX_IVS = _prefix(_SLSK_AUX_IVS, 16, 'SLSK aux IV')
SLSK_BODY_IV = _h(_SLSK_BODY_IV, 16, 'SLSK body IV') or b'\x00' * 16
SLSK_HDR_HMAC_IV = _h(_SLSK_HDR_HMAC_IV, 16, 'SLSK header HMAC IV') or b'\x00' * 16
SLSK_HMAC_KEY = _h(_SLSK_HMAC_KEY, 32, 'SLSK HMAC key') or b''
SLSK_PCK_KEY = _h(_SLSK_PCK_KEY, 0, 'SLSK PCK key')
SLSK_PCK_IV = _h(_SLSK_PCK_IV, 16, 'SLSK PCK IV') or b'\x00' * 16
SLSK_RSA_KEYS = [m for m in _SLSK_RSA_KEYS if m] or [1]

if not SLSK_MASTER_KEYS or not SLSK_KEY_IVS or not _SLSK_HMAC_KEY.strip():
    _missing.append('SLSK master keys / key IVs / HMAC key (second_loader, secure_kernel '
                    'and every key derived from them will be missing)')
elif not _SLSK_BODY_IV.strip() or not _SLSK_HDR_HMAC_IV.strip():
    _missing.append('SLSK body IV / header HMAC IV')
if _SLSK_RSA_KEYS == []:
    _missing.append('SLSK RSA moduli (header signature check only)')

ENC_KEY = _h(_ENC_KEY, 16, 'ENC_KEY')
ENC_IV = _h(_ENC_IV, 16, 'ENC_IV') or SLSK_BODY_IV

if _missing:
    sys.stderr.write('[keys.py] missing: ' + '; '.join(_missing) + '\n')


def register_npdrm_keys(store):
    for rev, key, iv in NPDRM_KEYS:
        store.register(KeyType.NPDRM, SceType.SELF, rev, key, iv,
                       0x00000000000, 0xFFFFFFFFFFFFFFFFFFFFFF, SelfType.APP)


# Populated at runtime by pup_fiction.py (sceutils reads keys.SCE_KEYS).
# SPKG keys are registered here too so scedecrypt.py works standalone.
SCE_KEYS = KeyStore()
for _key, _iv, _label in SPKG_KEYS:
    SCE_KEYS.register(KeyType.METADATA, SceType.SPKG, 0, _key, _iv,
                      0x00000000000, 0xFFFFFFFFFFFFFFFFFFFFFF, SelfType.NONE)
register_npdrm_keys(SCE_KEYS)
