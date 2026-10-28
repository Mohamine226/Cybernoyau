"""Outils partages par les tests."""
import struct


def make_pe(path, extra=b"", timestamp=1_600_000_000):
    """PE32 minimal valide (1 section) pour tester l'analyseur sans binaire reel."""
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64
    coff = struct.pack("<HHIIIHH", 0x14C, 1, timestamp, 0, 0, 0xE0, 0x102)
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 1, 0, 0x200, 0, 0,
                      0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200, 4, 0, 0, 0,
                      4, 0, 0, 0x2000, 0x200, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"\x00" * (0xE0 - len(opt))
    data = (b"\x90" * 64) + extra
    data += b"\x00" * ((-len(data)) % 0x200)
    sec = struct.pack("<8sIIIIIIHHI", b".text", 0x1000, 0x1000, len(data), 0x200,
                      0, 0, 0, 0, 0x60000020)
    header = dos + b"PE\x00\x00" + coff + opt + sec
    header += b"\x00" * (0x200 - len(header))
    path.write_bytes(header + data)
    return path
