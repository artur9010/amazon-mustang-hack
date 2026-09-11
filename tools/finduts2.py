from elftools.elf.elffile import ELFFile
f = open("/home/artur9010/dev/amazon-mustang-hack/kernel/vmlinux","rb")
e = ELFFile(f)
k = e.get_section_by_name('.kernel')
KBASE = k['sh_addr']; blob = k.data()
needle = b"4.9.117-g08fe75b-dirty\x00"
pos = 0
while True:
    idx = blob.find(needle, pos)
    if idx < 0: break
    print("=== @ %#x ===" % (KBASE+idx))
    print("before:", repr(blob[idx-135:idx]))
    print("after: ", repr(blob[idx+len(needle):idx+len(needle)+80]))
    pos = idx + 1
