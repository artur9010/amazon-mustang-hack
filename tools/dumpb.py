from elftools.elf.elffile import ELFFile
import struct, sys
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
k = e.get_section_by_name('.kernel')
KBASE = k['sh_addr']; blob = k.data()
def dump(a, n=0x50):
    print("--- %#x ---" % a)
    for off in range(0, n, 16):
        vals = struct.unpack_from('<4I', blob, a - KBASE + off)
        print("  +%02x: %08x %08x %08x %08x" % (off, *vals))
dump(int(sys.argv[1], 16))
