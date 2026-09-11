import re, subprocess, collections
from elftools.elf.elffile import ELFFile
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
syms = {}
for sec in e.iter_sections():
    if sec.header['sh_type'] == 'SHT_SYMTAB':
        for s in sec.iter_symbols():
            if s.name and s['st_value'] and s.name not in syms:
                syms[s.name] = s['st_value']
k = e.get_section_by_name('.kernel')
KBASE = k['sh_addr']; blob = k.data()
import struct
# find all "movw rX, #lo" followed within 8 bytes by "movt rX(same), #hi" patterns
# arm encodings: movw: cond 0011 0000 imm4 rd imm12 ; movt: cond 0011 0100 imm4 rd imm12
hist = collections.Counter()
for off in range(0, len(blob) - 16, 4):
    w1 = struct.unpack_from('<I', blob, off)[0]
    if (w1 & 0x0ff00000) != 0x03000000: continue
    w2 = struct.unpack_from('<I', blob, off + 4)[0]
    if (w2 & 0x0ff00000) != 0x03400000: continue
    rd1 = (w1 >> 12) & 0xf; rd2 = (w2 >> 12) & 0xf
    if rd1 != rd2: continue
    imm1 = ((w1 >> 4) & 0xf000) | (w1 & 0xfff)
    imm2 = ((w2 >> 4) & 0xf000) | (w2 & 0xfff)
    addr = (imm2 << 16) | imm1
    if 0xc1100000 <= addr < 0xc1251000:
        hist[addr] += 1
for a, c in hist.most_common(15):
    print("%#010x  refs=%d" % (a, c))
