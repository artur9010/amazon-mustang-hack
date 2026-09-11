from elftools.elf.elffile import ELFFile
import struct
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
k = e.get_section_by_name('.kernel')
KBASE = k['sh_addr']; blob = k.data()
KEND_FILE = KBASE + len(blob)          # 0xc1251000
BSS_START = 0xc11d9000
BSS_END   = 0xc12d9000
IMG_LO, IMG_HI = 0xc0008000, BSS_END

def rd32(a):
    if a >= KBASE and a < KEND_FILE and (a & 3) == 0:
        return struct.unpack_from('<I', blob, a - KBASE)[0]
    if a >= KEND_FILE and a < BSS_END:   # bss tail not in file => zeros
        return 0
    return None
def writable(a):
    # writable data window guess: validate modprobe_path 0xc111488c inside
    return 0xc10a0000 <= a < BSS_END - 4

hits = []
for S in range(0xc10a0000, min(KEND_FILE, BSS_END) - 0x40, 4):
    nents = rd32(S + 8)
    if nents != 0: continue
    if rd32(S + 0x18) != S + 0x18: continue      # empty evict_node (no WARN)
    Kc = rd32(S + 0x38)
    if Kc is None or not (IMG_LO <= Kc < IMG_HI - 0x14300): continue
    if not writable(Kc + 0x141c8): continue
    if rd32(Kc + 0x1429c) != 0: continue          # skip mm counter atomics
    D = rd32(Kc + 4)
    if D is None or not (IMG_LO <= D < IMG_HI): continue
    if not writable(D + 0x538): continue
    hits.append((S, Kc, D))
    if len(hits) >= 25: break
for S, Kc, D in hits:
    print("S=%#x K=%#x D=%#x   *(S+0x24)reg=%#x *(S+0x28)type=%#x" % (S, Kc, D, rd32(S+0x24) or 0, rd32(S+0x2c) or 0))
print("total", len(hits))
