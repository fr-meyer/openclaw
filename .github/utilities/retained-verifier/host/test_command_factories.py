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
           '/tmp/x/out/ocv-test.raw','/tmp/x/out/kernel.bin','/tmp/x/out/initrd.img',
           '/tmp/x/out/integrated-test.raw'))
        for uid,gid in ((0,1001),(1001,0),('1001',1001),(1001,True)):
            with self.assertRaises(c.Refusal):c.own_mkosi_outputs('/tmp/x',uid,gid)
    def test_security_origin_has_only_fixed_url_index_and_distinct_captured_paths(self):
        for kind,leaf,output in [('release','InRelease','SecurityInRelease'),
                                 ('packages','main/binary-amd64/Packages.xz','SecurityPackages.xz')]:
            argv=c.debian_metadata_curl('/tmp/ocv-public',kind,origin='security')
            self.assertEqual(argv[-1],'https://security.debian.org/debian-security/dists/bookworm-security/'+leaf)
            self.assertEqual(argv[argv.index('--output')+1],'/tmp/ocv-public/metadata/'+output)
            self.assertNotIn('--location',argv);self.assertEqual(argv[argv.index('--retry')+1],'0')
        self.assertEqual(c.gpgv_metadata('/tmp/ocv-public',origin='security')[-1],
                         '/tmp/ocv-public/metadata/SecurityInRelease')
        for origin in ('other','security/../main','https://example.invalid'):
            with self.subTest(origin=origin),self.assertRaises(c.Refusal):c.debian_metadata_curl('/tmp/ocv-public','release',origin)
            with self.assertRaises(c.Refusal):c.gpgv_metadata('/tmp/ocv-public',origin)
    def test_repair_download_has_one_fixed_main_url_output_size_and_no_redirect_or_retry(self):
        argv=c.debian_metadata_curl('/tmp/ocv-public','repair')
        self.assertEqual(argv[-1],'https://deb.debian.org/debian/pool/main/libs/libselinux/selinux-utils_3.4-1+b6_amd64.deb')
        self.assertEqual(argv[argv.index('--output')+1],'/tmp/ocv-public/metadata/SelinuxUtils.deb')
        self.assertEqual(argv[argv.index('--max-filesize')+1],'126432')
        self.assertEqual(argv[argv.index('--retry')+1],'0');self.assertNotIn('--location',argv)
        for origin in ('security','other','https://example.invalid'):
            with self.subTest(origin=origin),self.assertRaises(c.Refusal):c.debian_metadata_curl('/tmp/ocv-public','repair',origin)
    def test_test_roster_comes_only_from_known_manifest_rows(self):
        rows={'host/test_a.py':{},'host/not_a_test.py':{},'host/deep/test_b.py':{},'apt/test_archive_policy.py':{}}
        self.assertEqual(r.selected_paths(rows,'host'),['host/test_a.py'])
        self.assertEqual(r.selected_paths(rows,'archive'),['apt/test_archive_policy.py'])
        with self.assertRaises(ValueError):r.selected_paths(rows,'runtime')
        with self.assertRaises(ValueError):r.selected_paths(rows,'unknown')


if __name__=='__main__':unittest.main()
