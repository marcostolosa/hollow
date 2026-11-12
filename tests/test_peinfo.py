"""Regression tests for read-only PE metadata inspection."""
import struct
import unittest
from tools.peinfo import PEFormatError, inspect


def sample_pe():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = bytes((80, 69, 0, 0))
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 240, 2)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<I", data, opt + 56, 0x3000)
    struct.pack_into("<I", data, opt + 60, 0x200)
    struct.pack_into("<I", data, opt + 108, 0)
    section = opt + 240
    struct.pack_into("<IIII", data, section + 8, 0x100, 0x1000, 0x100, 0x200)
    return data


class TestPEInspection(unittest.TestCase):
    def test_valid_pe(self):
        result = inspect(bytes(sample_pe()))
        self.assertEqual(result["machine"], "0x8664")
        self.assertEqual(result["size_of_image"], 0x3000)

    def test_truncated_dos_header(self):
        with self.assertRaises(PEFormatError):
            inspect(b"MZ")

    def test_bad_pe_offset(self):
        data = sample_pe()
        struct.pack_into("<I", data, 0x3C, 0xFFFFFF00)
        with self.assertRaises(PEFormatError):
            inspect(bytes(data))

    def test_wrong_architecture(self):
        data = sample_pe()
        struct.pack_into("<H", data, 0x84, 0x14C)
        with self.assertRaises(PEFormatError):
            inspect(bytes(data))

    def test_oversized_section(self):
        data = sample_pe()
        struct.pack_into("<I", data, 0x98 + 240 + 8 + 4, 0x5000)
        with self.assertRaises(PEFormatError):
            inspect(bytes(data))

    def test_truncated_section_table(self):
        with self.assertRaises(PEFormatError):
            inspect(bytes(sample_pe()[:0x190]))


if __name__ == "__main__":
    unittest.main()
