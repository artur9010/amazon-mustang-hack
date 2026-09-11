#!/usr/bin/env python3
"""lk_xref.py - base-independent string xref resolver for Amazon/MTK UFBL (mustang lk.img).

Background (SESSION 12): lk.img is Thumb-2 position-independent code.  Strings
are materialised with the idiom

    ldr  rT, [pc, #imm]     ; 16-bit T1 (offset = imm8*4) or 32-bit ldr.w (imm12)
    add  rT, pc             ; 16-bit 0x44xx, or add.w

so the absolute (base-relative) target is

    target = (add_insn_addr + 4) + *(Align(ldr_pc,4) + offset)

This script scans every 2-byte offset (so it survives the ARM vector stub and
literal pools without de-syncing), resolves every add-pc, and prints references
to printable strings.  Use it to map lk.img functions even though the image is
relocated at runtime (base 0xFF400000; see README SESSION 12).

Usage:
    nix-shell -p python3Packages.capstone --run \
        'python3 tools/lk_xref.py /path/lk.img [regex]'
"""
import re
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

IMG = sys.argv[1] if len(sys.argv) > 1 else "/tmp/opencode/mustang-dumps/lk.img"
FILT = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None

d = open(IMG, "rb").read()
N = len(d)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)

RN = {"sp": 13, "lr": 14, "pc": 15, "ip": 12, "sb": 9, "sl": 10, "fp": 11}


def rnum(tok):
    tok = tok.strip()
    if tok in RN:
        return RN[tok]
    m = re.match(r"r(\d+)$", tok)
    return int(m.group(1)) if m else None


def cstr(off):
    if off < 0 or off >= N:
        return None
    e = off
    while e < N and d[e] != 0 and e - off <= 200:
        e += 1
    try:
        s = d[off:e].decode()
    except Exception:
        return None
    if not s or any(ord(c) < 32 or ord(c) > 126 for c in s):
        return None
    return s


# pass 1: collect ldr-literal (dest reg, literal pool address)
ldrs = {}
for o in range(0x200, N - 4, 2):
    one = list(md.disasm(d[o:o + 4], o))
    if not one:
        continue
    ins = one[0]
    if ins.mnemonic == "ldr" and "[pc" in ins.op_str and ins.op_str.endswith("]"):
        rd = rnum(ins.op_str.split(",")[0])
        if rd is None:
            continue
        try:
            imm = int(ins.op_str.split("#")[1].split("]")[0], 0)
        except Exception:
            continue
        pool = ((o + 4) & ~3) + imm
        if pool + 4 <= N:
            ldrs[o] = (rd, pool)

# pass 2: resolve add rT, pc against the nearest preceding ldr into rT
for o in range(0x200, N - 4, 2):
    one = list(md.disasm(d[o:o + 4], o))
    if not one:
        continue
    ins = one[0]
    if ins.mnemonic == "add" and "pc" in ins.op_str:
        rd = rnum(ins.op_str.split(",")[0])
        if rd is None:
            continue
        for back in range(2, 33, 2):
            j = o - back
            if j in ldrs and ldrs[j][0] == rd:
                w = struct.unpack_from("<I", d, ldrs[j][1])[0]
                tgt = (o + 4 + w) & 0xFFFFFFFF
                s = cstr(tgt)
                if s and (FILT is None or FILT.search(s)):
                    print("%#08x addpc(%d) ldr@%#x -> %#08x %r" %
                          (o, ins.size, j, tgt, s))
                break
