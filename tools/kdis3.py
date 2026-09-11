from elftools.elf.elffile import ELFFile
from capstone import *
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
import sys
syms = {}
addr2sym = {}
for sec in e.iter_sections():
    if sec.header['sh_type'] == 'SHT_SYMTAB':
        for s in sec.iter_symbols():
            if s.name and s['st_value']:
                syms.setdefault(s.name, s['st_value'])
                addr2sym.setdefault(s['st_value'], s.name)
k = e.get_section_by_name('.kernel')
base, data = k['sh_addr'], k.data()
md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
def sym(a):
    if a in addr2sym: return addr2sym[a]
    return "?"
start = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0xc0584afc
length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x90
import sys
for i in md.disasm(data[start-base:start-base+length], start):
    extra = ""
    if i.mnemonic == 'bl': extra = "   ; " + sym(int(i.op_str[1:], 16))
    print("%#010x: %-8s %-28s%s" % (i.address, i.mnemonic, i.op_str, extra))
