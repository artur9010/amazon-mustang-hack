from elftools.elf.elffile import ELFFile
import struct
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
k = e.get_section_by_name('.kernel')
KBASE = k['sh_addr']; blob = k.data()
run = 0; start = None
found = []
lo, hi = 0xc1000000 - KBASE, min(len(blob) - 8, 0xc1251000 - KBASE)
for off in range(lo, hi, 4):
    a = KBASE + off
    v1 = struct.unpack_from('<I', blob, off)[0]
    v2 = struct.unpack_from('<I', blob, off + 4)[0]
    if v1 == a and v2 == a:
        if run == 0: start = a
        run += 1
    else:
        if run >= 32:
            found.append((start, run))
        run = 0
if run >= 32: found.append((start, run))
for a, r in found:
    print("run: base=%#x count=%d spans=%#x .. %#x" % (a, r, a, a + (r-1)*8))
