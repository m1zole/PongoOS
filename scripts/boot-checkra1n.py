#!/usr/bin/env python3
#
#  Copyright (C) 2019-2023 checkra1n team
#  This file is part of pongoOS.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# 
import usb.core
import struct
import sys
import argparse
import time

parser = argparse.ArgumentParser(description='loader')

parser.add_argument('-k', '--kpf', dest='kpf', help='path to kernel patch finder')
parser.add_argument('-r', '--ramdisk', dest='ramdisk', help='path to ramdisk')
parser.add_argument('-o', '--overlay', dest='overlay', help='path to overlay')

args = parser.parse_args()

dev = usb.core.find(idVendor=0x05ac, idProduct=0x4141)
if dev is None:
    print("Waiting for device...")

    while dev is None:
        dev = usb.core.find(idVendor=0x05ac, idProduct=0x4141)
        if dev is not None:
            dev.set_configuration()
            break
        time.sleep(2)
else:
    dev.set_configuration()

kpf = open(args.kpf, "rb").read()
overlay = open(args.overlay, "rb").read()
ramdisk = open(args.ramdisk, "rb").read()

# cmd
dev.ctrl_transfer(0x21, 3, 0, 0, "fuse lock\n")
print("fuse lock done")
dev.ctrl_transfer(0x21, 3, 0, 0, "sep auto\n", 33333)
print("sep auto done")
time.sleep(1)

#kpf
time.sleep(1)
print("Loading kpf...")
kpf = open(args.kpf, "rb").read()
kpf_size = len(kpf)
dev.ctrl_transfer(0x21, 2, 0, 0, 0)
dev.ctrl_transfer(0x21, 1, 0, 0, struct.pack('I', kpf_size))

dev.write(2, kpf, 1000000)
dev.ctrl_transfer(0x21, 4, 0, 0, 0)
dev.ctrl_transfer(0x21, 3, 0, 0, "modload\n", 33333)
print("kpf successfully.")

#ramdisk
time.sleep(1)
print("Loading ramdisk...")
ramdisk = open(args.ramdisk, "rb").read()
ramdisk_size = len(ramdisk)
dev.ctrl_transfer(0x21, 2, 0, 0, 0)
dev.ctrl_transfer(0x21, 1, 0, 0, struct.pack('I', ramdisk_size))

dev.write(2, ramdisk, 1000000)
dev.ctrl_transfer(0x21, 4, 0, 0, 0)
dev.ctrl_transfer(0x21, 3, 0, 0, "ramdisk\n")
print("ramdisk successfully.")

#overlay
time.sleep(1)
print("Loading overlay...")
overlay = open(args.overlay, "rb").read()
overlay_size = len(overlay)
dev.ctrl_transfer(0x21, 2, 0, 0, 0)
dev.ctrl_transfer(0x21, 1, 0, 0, struct.pack('I', overlay_size))

dev.write(2, overlay, 1000000)
dev.ctrl_transfer(0x21, 4, 0, 0, 0)
dev.ctrl_transfer(0x21, 3, 0, 0, "overlay\n")
print("overlay successfully.")

#cmd
time.sleep(1)
dev.ctrl_transfer(0x21, 3, 0, 0, "kpf_flags 0x00000000\n")
dev.ctrl_transfer(0x21, 3, 0, 0, "checkra1n_flags 0x00000000\n")
dev.ctrl_transfer(0x21, 3, 0, 0, "xargs rootdev=md0 -v\n")
time.sleep(1)
dev.ctrl_transfer(0x21, 3, 0, 0, "xfb\n")
time.sleep(1)
dev.ctrl_transfer(0x21, 4, 0, 0, 0)
try:
    dev.ctrl_transfer(0x21, 3, 0, 0, "bootx\n")
except:
    # if the device disconnects without acknowledging it usually means it succeeded
    print("Success.")
