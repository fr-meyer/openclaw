import unittest
import command_factories as c
import run_unit_tests as r


class FactoryTests(unittest.TestCase):
    def test_apt_uses_fixed_official_native_package_roots_and_sources(self):
        vector=c.ubuntu_apt_install('/tmp/ocv-public')
        self.assertEqual(vector[:4],('/usr/bin/sudo','-n','--','/usr/bin/apt-get'))
        self.assertIn('mkosi=20.2-1',vector);self.assertNotIn('trusted=yes',c.ubuntu_sources().decode())
        self.assertIn('systemd-boot',vector)
        self.assertIn('kmod',vector);self.assertIn('e2fsprogs',vector)
        self.assertIn('/usr/bin/bootctl',c.dpkg_query('owners'))
        self.assertIn('systemd-boot',c.dpkg_query('versions'))
        self.assertIn('kmod',c.dpkg_query('versions'))
        self.assertIn('e2fsprogs',c.dpkg_query('versions'))
        self.assertEqual(c.dpkg_query('kmod_files')[-2:],('--listfiles','kmod'))
        self.assertEqual(c.dpkg_query('e2fsprogs_files')[-2:],('--listfiles','e2fsprogs'))
        self.assertNotIn('Check-Valid-Until=false',' '.join(vector))
    def test_metadata_urls_and_outputs_are_fixed_not_user_commands(self):
        for kind in ('release','packages'):
            args=c.debian_metadata_curl('/tmp/ocv-public',kind)
            self.assertTrue(args[-1].startswith('https://deb.debian.org/debian/dists/bookworm/'))
            self.assertNotIn('--location',args)
        with self.assertRaises(c.Refusal):c.debian_metadata_curl('/tmp/ocv-public','secret')
    def test_paths_and_chown_scope_have_no_shell_escape(self):
        for value in ('/','/tmp/../etc','/tmp/x;bad','/tmp/x$(bad)'):
            with self.assertRaises(c.Refusal):c.ubuntu_apt_update(value)
        with self.assertRaises(c.Refusal):c.own_project_chown('/tmp/x','prepare','1001:1001')
        with self.assertRaises(c.Refusal):c.own_project_chown('/tmp/x','outside','1001:1001')
        self.assertEqual(c.own_mkosi_outputs('/tmp/x',1001,1001),
          ('/usr/bin/sudo','-n','--','/usr/bin/chown','--from=1001:1001','--','0:0',
           '/tmp/x/out/ocv-test.raw','/tmp/x/out/kernel.bin','/tmp/x/out/initrd.img'))
        for uid,gid in ((0,1001),(1001,0),('1001',1001),(1001,True)):
            with self.assertRaises(c.Refusal):c.own_mkosi_outputs('/tmp/x',uid,gid)
    def test_test_roster_comes_only_from_known_manifest_rows(self):
        rows={'host/test_a.py':{},'host/not_a_test.py':{},'host/deep/test_b.py':{},'apt/test_archive_policy.py':{}}
        self.assertEqual(r.selected_paths(rows,'host'),['host/test_a.py'])
        self.assertEqual(r.selected_paths(rows,'archive'),['apt/test_archive_policy.py'])
        with self.assertRaises(ValueError):r.selected_paths(rows,'runtime')
        with self.assertRaises(ValueError):r.selected_paths(rows,'unknown')


if __name__=='__main__':unittest.main()
