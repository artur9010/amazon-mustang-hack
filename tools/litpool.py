import struct, sys
from elftools.elf.elffile import ELFFile
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
k = e.get_section_by_name('.kernel')
KBASE = k['sh_addr']; blob = k.data()
# literal at pc(0xc1047030)+8+0x1a0 = 0xc10471d8
for target in [0xc10471d8, 0xc10471d4]:
    off = target - KBASE
    print("%#x: %#010x" % (target, struct.unpack_from('<I', blob, off)[0]))
