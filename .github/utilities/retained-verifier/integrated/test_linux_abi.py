"""Generic fixed Linux wire-ABI vectors, independent of the replay host ABI."""
from pathlib import Path
import sys
import unittest

import probe
from protocol import Refusal


class LinuxDeviceABI(unittest.TestCase):
    def test_fixed_glibc236_vectors_include_both_component_high_bits(self):
        # Fixed independent vectors for glibc2.36 bits/sysmacros.h, not host os.*.
        vectors=((0,0,0),(1,3,0x103),(8,1,0x801),(0,0x100,0x100000),
            (0x1000,0,0x100000000000),(0xabc,0xdef,0xdabcef),
            (0x12345678,0x9abcdef0,0x123459abcde678f0),
            (0x80000000,0,0x8000000000000000),
            (0,0x80000000,0x0000080000000000),
            (0xffffffff,0xffffffff,0xffffffffffffffff))
        for major,minor,device in vectors:
            with self.subTest(major=major,minor=minor):
                self.assertEqual(probe.linux_makedev(major,minor),device)
                self.assertEqual(probe.linux_major(device),major)
                self.assertEqual(probe.linux_minor(device),minor)

    def test_component_edges_round_trip_without_truncation(self):
        values=(0,1,0xff,0x100,0xfff,0x1000,0xfffff,0x100000,0x7fffffff,0x80000000,0xffffffff)
        for major in values:
            for minor in values:
                device=probe.linux_makedev(major,minor)
                self.assertEqual((probe.linux_major(device),probe.linux_minor(device)),(major,minor))

    def test_negative_bool_noninteger_and_oversized_values_refuse(self):
        for value in (-1,True,False,1.0,'1',None,1<<32):
            for args in ((value,0),(0,value)):
                with self.subTest(args=args),self.assertRaisesRegex(Refusal,'probe.linux_device_component'):
                    probe.linux_makedev(*args)
        for value in (-1,True,False,1.0,'1',None,1<<64):
            for function in (probe.linux_major,probe.linux_minor):
                with self.subTest(value=value,function=function),self.assertRaisesRegex(Refusal,'probe.linux_device'):
                    function(value)

    def test_linux_fdinfo_flags_have_fixed_target_values(self):
        self.assertEqual((probe.LINUX_O_RDONLY,probe.LINUX_O_WRONLY,
                          probe.LINUX_O_APPEND,probe.LINUX_O_LARGEFILE),(0,1,1024,32768))
        value=probe.fdinfo('pos:\t0\nflags:\t0102001\nmnt_id:\t27\nino:\t17963\n')
        self.assertEqual(value['flags'],33793)
        for flag in ('-1','true','0x8401','102008'):
            with self.subTest(flag=flag),self.assertRaises(Refusal):
                probe.fdinfo(f'pos:\t0\nflags:\t{flag}\nmnt_id:\t27\nino:\t17963\n')


if __name__=='__main__':unittest.main()
