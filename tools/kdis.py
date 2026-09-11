import sys
from elftools.elf.elffile import ELFFile
from capstone import *
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
syms, sizes = {}, {}
for sec in e.iter_sections():
    if sec.header['sh_type'] == 'SHT_SYMTAB':
        for s in sec.iter_symbols():
            if s.name and s['st_value'] and s.name not in syms:
                syms[s.name] = s['st_value']; sizes[s.name] = s['st_size']
k = e.get_section_by_name('.kernel')
base, data = k['sh_addr'], k.data()
md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
md.detail = False
for name in sys.argv[1:]:
    a = syms[name]; ln = sizes.get(name) or 0x100
    print("=== %s @ %#x size %d ===" % (name, a, sizes.get(name, 0)))
    for i in md.disasm(data[a-base:a-base+ln], a):
        print("%#010x: %-8s %s" % (i.address, i.mnemonic, i.op_str))
