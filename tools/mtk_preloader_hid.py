#!/usr/bin/env python3
"""mtk_preloader_hid.py - talk to the Amazon/MTK preloader over its HID transport.

SESSION 13: a powered-off Fire 7 (mustang) enumerates as 1949:20ff (Amazon VID,
PID 0x20FF = the MediaTek "MTK Preloader" PID) as a HID interface with a dummy
report descriptor and two 4-byte interrupt endpoints.  The Amazon preloader used
by aftv2-tools exposes built-in, Download-Agent-less commands over this byte
stream:

    0xD1 read32(addr, n_words)   -> echo cmd/addr/n, 0x0000, n*u32, 0x0000
    0xD4 write32(addr, words[])  -> echo cmd/addr/n, 0x0000, n*u32, 0x0000

Handshake: host 0xA0 0x0A 0x50 0x05  -> dev 0x5F 0xF5 0xAF 0xFA

Because this runs in the preloader (below LK), read32/write32 can reach the MSDC
controller (see aftv2-tools read_mmc.py) and therefore the raw eMMC - that is a
path to persistent unlock.  This tool defaults to *read-only*; write32 is only
reachable via an explicit subcommand and is guarded.

Run (root needed for USB write; chmod the node first):
    lsusb -d 1949:20ff                 # note bus/dev
    sudo chmod 666 /dev/bus/usb/001/003
    nix-shell -p python3Packages.pyusb --run \
        'python3 tools/mtk_preloader_hid.py handshake'
    nix-shell -p python3Packages.pyusb --run \
        'python3 tools/mtk_preloader_hid.py read32 0x00100000 4'
"""
import argparse
import struct
import sys
import time

import usb.core
import usb.util

VID, PID = 0x1949, 0x20FF


class PreloaderHID:
    def __init__(self):
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise SystemExit("[-] 1949:20ff not present")
        try:
            self.dev.detach_kernel_driver(0)
        except Exception:
            pass
        usb.util.claim_interface(self.dev, 0)
        cfg = self.dev.get_active_configuration()
        itf = cfg[(0, 0)]

        def m(direction):
            return lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == direction

        self.ep_out = usb.util.find_descriptor(itf, custom_match=m(usb.util.ENDPOINT_OUT))
        self.ep_in = usb.util.find_descriptor(itf, custom_match=m(usb.util.ENDPOINT_IN))
        self.pktsize = self.ep_out.wMaxPacketSize or 4

    # --- raw transport -----------------------------------------------------
    def write(self, data):
        for i in range(0, len(data), self.pktsize):
            self.ep_out.write(bytes(data[i:i + self.pktsize]), timeout=3000)

    def read(self, n, timeout=3000):
        buf = bytearray()
        deadline = time.time() + timeout / 1000.0
        while len(buf) < n:
            try:
                chunk = bytes(self.ep_in.read(n - len(buf), timeout=timeout))
            except usb.core.USBTimeoutError:
                if time.time() > deadline:
                    break
                continue
            if not chunk:
                break
            buf += chunk
        return bytes(buf)

    def read_exact(self, n, what=""):
        d = self.read(n)
        if len(d) != n:
            raise SystemExit("[-] short read for %s: got %d want %d (%s)" %
                             (what, len(d), n, d.hex()))
        return d

    # --- MTK preloader protocol -------------------------------------------
    def info(self):
        try:
            print("[*] manufacturer: %r" % self.dev.manufacturer)
            print("[*] product     : %r" % self.dev.product)
            print("[*] serial      : %r" % self.dev.serial_number)
        except Exception as e:
            print("[*] string descriptors unavailable: %s" % e)
        try:
            rdesc = self.dev.ctrl_transfer(0x81, 0x06, 0x2200, 0, 255, timeout=2000)
            print("[*] HID report descriptor (%d bytes): %s" %
                  (len(rdesc), bytes(rdesc).hex()))
        except Exception as e:
            print("[*] report descriptor: %s" % e)

    def listen(self, secs=6):
        print("[*] listening on EP IN for %ds ..." % secs)
        deadline = time.time() + secs
        n = 0
        while time.time() < deadline:
            try:
                d = bytes(self.ep_in.read(64, timeout=500))
            except usb.core.USBTimeoutError:
                continue
            except Exception as e:
                print("[-] read: %s" % e)
                break
            if d:
                n += 1
                print("    %s  %s" % (time.strftime("%H:%M:%S"), d.hex()))
        print("[*] %d report(s) received" % n)

    def handshake(self, verbose=True):
        for b in (0xA0, 0x0A, 0x50, 0x05):
            self.write(bytes([b]))
            got = self.read(1)
            want = (~b) & 0xFF
            if verbose:
                print("    %#04x -> %s (want %#04x)" %
                      (b, got.hex() or "<timeout>", want))
            if got != bytes([want]):
                return False
        return True

    def read32(self, addr, nwords):
        self.write(b"\xd1")
        echo = self.read_exact(1, "cmd echo")
        if echo != b"\xd1":
            raise SystemExit("[-] read32 cmd not echoed: %s" % echo.hex())
        for val, name in ((addr, "addr"), (nwords, "count")):
            self.write(struct.pack(">I", val))
            got = struct.unpack(">I", self.read_exact(4, name + " echo"))[0]
            if got != val:
                raise SystemExit("[-] %s echo mismatch: %#x != %#x" % (name, got, val))
        arg = self.read_exact(2, "arg check")
        if arg != b"\x00\x00":
            raise SystemExit("[-] arg check: %s" % arg.hex())
        words = list(struct.unpack(">%dI" % nwords, self.read_exact(4 * nwords, "data")))
        status = self.read_exact(2, "status")
        if status != b"\x00\x00":
            raise SystemExit("[-] status: %s" % status.hex())
        return words

    def write32(self, addr, words):
        self.write(b"\xd4")
        if self.read_exact(1, "cmd echo") != b"\xd4":
            raise SystemExit("[-] write32 cmd not echoed")
        for val, name in ((addr, "addr"), (len(words), "count")):
            self.write(struct.pack(">I", val))
            got = struct.unpack(">I", self.read_exact(4, name + " echo"))[0]
            if got != val:
                raise SystemExit("[-] %s echo mismatch" % name)
        if self.read_exact(2, "arg check") != b"\x00\x00":
            raise SystemExit("[-] arg check")
        for w in words:
            self.write(struct.pack(">I", w))
            got = struct.unpack(">I", self.read_exact(4, "word echo"))[0]
            if got != w:
                raise SystemExit("[-] word echo mismatch")
        if self.read_exact(2, "status") != b"\x00\x00":
            raise SystemExit("[-] status")

    def close(self):
        try:
            usb.util.release_interface(self.dev, 0)
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("handshake")
    sub.add_parser("info")
    lp = sub.add_parser("listen")
    lp.add_argument("secs", nargs="?", type=int, default=6)
    rp = sub.add_parser("raw")
    rp.add_argument("hexbytes", nargs="+", help="e.g. a0 or a0 00 00 00")
    p = sub.add_parser("read32")
    p.add_argument("addr", type=lambda s: int(s, 0))
    p.add_argument("nwords", type=lambda s: int(s, 0))
    p = sub.add_parser("write32")
    p.add_argument("addr", type=lambda s: int(s, 0))
    p.add_argument("words", type=lambda s: int(s, 0), nargs="+")
    a = ap.parse_args()

    pl = PreloaderHID()
    print("[*] transport up (maxpkt=%d)" % pl.pktsize)
    if a.cmd == "info":
        pl.info()
        pl.close()
        return
    if a.cmd == "listen":
        pl.listen(a.secs)
        pl.close()
        return
    if a.cmd == "raw":
        data = bytes(int(x, 16) for x in a.hexbytes)
        print("[*] raw OUT: %s" % data.hex())
        pl.write(data)
        pl.listen(2)
        pl.close()
        return
    if not pl.handshake():
        raise SystemExit("[-] handshake failed")
    print("[+] handshake OK")

    if a.cmd == "handshake":
        pass
    elif a.cmd == "read32":
        words = pl.read32(a.addr, a.nwords)
        for i, w in enumerate(words):
            print("  %#010x: %#010x" % (a.addr + 4 * i, w))
    elif a.cmd == "write32":
        print("[!] write32 to %#x, %d word(s) - ensure this is what you want" % (a.addr, len(a.words)))
        pl.write32(a.addr, a.words)
        print("[+] write32 ok")
    pl.close()


if __name__ == "__main__":
    sys.exit(main())
