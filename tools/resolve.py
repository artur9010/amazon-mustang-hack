from elftools.elf.elffile import ELFFile
import sys
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
syms = {}
addr2sym = {}
for sec in e.iter_sections():
    if sec.header['sh_type'] == 'SHT_SYMTAB':
        for s in sec.iter_symbols():
            if s.name and s['st_value']:
                syms.setdefault(s.name, s['st_value'])
                addr2sym.setdefault(s['st_value'], s.name)
import bisect
addrs = sorted(addr2sym)
for a in sys.argv[1:]:
    v = int(a, 16)
    i = bisect.bisect_right(addrs, v) - 1
    base = addrs[i]
    print("%#x = %s+%#x" % (v, addr2sym[base], v - base))
