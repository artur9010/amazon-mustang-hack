from elftools.elf.elffile import ELFFile
from capstone import *
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
syms, sizes = {}, {}
addr2sym = {}
for sec in e.iter_sections():
    if sec.header['sh_type'] == 'SHT_SYMTAB':
        for s in sec.iter_symbols():
            if s.name and s['st_value']:
                if s.name not in syms:
                    syms[s.name] = s['st_value']; sizes[s.name] = s['st_size']
                    addr2sym.setdefault(s['st_value'], s.name)
k = e.get_section_by_name('.kernel')
base, data = k['sh_addr'], k.data()
md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
def sym(a):
    if a in addr2sym: return addr2sym[a]
    best = None
    for n, v in syms.items():
        if v <= a and (best is None or v > syms[best]):
            best = n
    return "%s+%#x" % (best, a - syms[best]) if best else "?"
for target in [0xc019c884, 0xc019caa0, 0xc0b1761c, 0xc0b176f0, 0xc0599b70, 0xc0583428, 0xc05a8314]:
    print("%#010x = %s" % (target, sym(target)))
print()
a = syms['kbase_jit_free']
for i in md.disasm(data[a-base+0x9c:a-base+0x1a0], a+0x9c):
    extra = ""
    if i.mnemonic == 'bl': extra = "   ; " + sym(int(i.op_str[1:], 16))
    print("%#010x: %-8s %-30s%s" % (i.address, i.mnemonic, i.op_str, extra))
