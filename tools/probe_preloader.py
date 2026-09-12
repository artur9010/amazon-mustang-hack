#!/usr/bin/env python3
"""probe_preloader.py - confirm the MediaTek preloader/USBDL transport.

SESSION 13 context: a Fire 7 (mustang) powered off and plugged into USB
enumerates as 1949:20ff (Amazon VID, MediaTek preloader PID 0x20FF) exposing a
HID interface with a *dummy* report descriptor and two 4-byte interrupt
endpoints.  0x20FF is listed as "MTK Preloader" in mtkclient's usb_ids.py (under
VID 0x0e8d); Amazon kept the PID and changed the VID.

This script only asks a question: does the device answer the standard MTK
preloader/BROM byte-pair handshake (0xA0->0x5F, 0x0A->0xF5, 0x50->0xAF,
0x05->0xFA) over the interrupt endpoints?

It does NOT send a Download Agent and does NOT read or write flash.

Run (root needed for USB write access; simplest is to chmod the node first):
    lsusb -d 1949:20ff                 # note bus/dev, e.g. Bus 001 Device 003
    sudo chmod 666 /dev/bus/usb/001/003
    nix-shell -p python3Packages.pyusb --run \
        'python3 tools/probe_preloader.py'
"""
import sys
import time

import usb.core
import usb.util

VID, PID = 0x1949, 0x20FF
HANDSHAKE = bytes([0xA0, 0x0A, 0x50, 0x05])


def main():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("[-] 1949:20ff not present")
        return 2
    print("[+] found 1949:20ff: bus %d addr %d" % (dev.bus, dev.address))

    # detach usbhid (also detaches the generic HID driver)
    try:
        dev.detach_kernel_driver(0)
        print("[*] detached kernel driver on interface 0")
    except Exception as e:
        print("[*] detach_kernel_driver: %s" % e)

    try:
        usb.util.claim_interface(dev, 0)
    except Exception as e:
        print("[!] claim_interface failed: %s" % e)
        return 3

    cfg = dev.get_active_configuration()
    itf = cfg[(0, 0)]
    ep_out = usb.util.find_descriptor(
        itf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress)
        == usb.util.ENDPOINT_OUT)
    ep_in = usb.util.find_descriptor(
        itf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress)
        == usb.util.ENDPOINT_IN)
    print("[*] ep_out=%#04x attr=%#x maxpkt=%d  ep_in=%#04x attr=%#x maxpkt=%d" %
          (ep_out.bEndpointAddress, ep_out.bmAttributes, ep_out.wMaxPacketSize,
           ep_in.bEndpointAddress, ep_in.bmAttributes, ep_in.wMaxPacketSize))

    ok = True
    for b in HANDSHAKE:
        want = (~b) & 0xFF
        try:
            ep_out.write(bytes([b]), timeout=2000)
            got = bytes(ep_in.read(1, timeout=2000))
        except Exception as e:
            print("[-] %#04x -> exception %s" % (b, e))
            ok = False
            break
        print("    %#04x -> %s (want %#04x) %s" %
              (b, got.hex() or "<timeout>", want, "OK" if got == bytes([want]) else "MISMATCH"))
        if got != bytes([want]):
            ok = False
            break

    try:
        usb.util.release_interface(dev, 0)
    except Exception:
        pass

    if ok:
        print("[+] MTK preloader handshake OK - interrupt transport carries USBDL")
        return 0
    print("[-] handshake failed - channel is not the standard MTK byte-pair protocol")
    return 1


if __name__ == "__main__":
    sys.exit(main())
