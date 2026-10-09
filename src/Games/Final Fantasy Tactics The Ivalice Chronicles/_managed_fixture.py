"""Inert PE/CLR-shaped bytes for static policy tests; never runnable code."""
import struct


def managed_bytes(tag=b'fixture'):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', data, 0x84, 0x8664, 1)
    struct.pack_into('<HH', data, 0x94, 240, 0x2000)
    struct.pack_into('<H', data, 0x98, 0x20b)
    struct.pack_into('<I', data, 0x98 + 108, 16)
    struct.pack_into('<II', data, 0x98 + 112 + 14 * 8, 0x2000, 72)
    struct.pack_into('<IIII', data, 0x98 + 240 + 8, 512, 0x2000, 512, 512)
    struct.pack_into('<IHHII', data, 512, 72, 2, 5, 0x2050, 32)
    struct.pack_into('<I', data, 528, 1)  # IL-only, no native entry point
    data[592:596] = b'BSJB'
    data[640:640 + len(tag)] = tag
    return bytes(data)
