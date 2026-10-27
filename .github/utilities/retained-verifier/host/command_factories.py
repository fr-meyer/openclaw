"""Finite source-owned CI command vectors; constructing argv has no effect."""
from pathlib import PurePosixPath
import re

HOST_PACKAGES=('mkosi=20.2-1','qemu-system-x86','fdisk','debian-archive-keyring','curl','gpgv',
               'systemd-boot','kmod','e2fsprogs')
SUITES=('archive','outer','native','runtime','apt','build','bootstrap','host','consumer')


class Refusal(ValueError):pass


def require(ok,why):
    if not ok:raise Refusal(why)


def path(value):
    require(type(value) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+',value),'command_path')
    p=PurePosixPath(value)
    require(str(p)==value and '..' not in p.parts and value!='/','command_path')
    return value


def project_path(project, relative):
    root=path(project)
    require(type(relative) is str and not relative.startswith('/') and '..' not in PurePosixPath(relative).parts,
            'command_relative')
    return root+'/'+relative


def git_read(workspace, kind):
    path(workspace)
    table={'head':('rev-parse','HEAD'),'tree':('rev-parse','HEAD^{tree}'),
      'clean':('diff','--quiet','--exit-code','--','.github/utilities/retained-verifier',
               '.github/workflows/authorized-beta-focused-validation.yml')}
    require(kind in table,'git_kind')
    return ('/usr/bin/git','-C',workspace)+table[kind]


def ubuntu_apt_base(project):
    return ('/usr/bin/sudo','-n','--','/usr/bin/apt-get','-q',
      '-o','Dir::Etc::sourcelist='+project_path(project,'ubuntu.sources.list'),
      '-o','Dir::Etc::sourceparts=-','-o','Dir::Etc::main=/dev/null','-o','Dir::Etc::parts=-',
      '-o','Dir::State::lists='+project_path(project,'ubuntu-lists'),
      '-o','Dir::Cache::archives='+project_path(project,'ubuntu-archives'),
      '-o','APT::Update::Error-Mode=any','-o','Acquire::Retries=0')


def ubuntu_apt_update(project):return ubuntu_apt_base(project)+('update',)
def ubuntu_apt_install(project):
    return ubuntu_apt_base(project)+('install','--yes','--no-install-recommends')+HOST_PACKAGES


def debian_metadata_curl(project, kind):
    table={'release':('InRelease',196608),
           'packages':('main/binary-amd64/Packages.xz',16777216)}
    require(kind in table,'metadata_kind');name,cap=table[kind]
    output=project_path(project,'metadata/'+('InRelease' if kind=='release' else 'Packages.xz'))
    return ('/usr/bin/curl','--fail','--silent','--show-error','--proto','=https','--tlsv1.2',
      '--retry','0','--connect-timeout','20','--max-time','120','--max-filesize',str(cap),
      '--output',output,'https://deb.debian.org/debian/dists/bookworm/'+name)


def gpgv_metadata(project):
    return ('/usr/bin/gpgv','--status-fd','1','--keyring',project_path(project,'metadata/keyring.gpg'),
            project_path(project,'metadata/InRelease'))


def dpkg_query(kind):
    table={'versions':('--show','--showformat=${binary:Package}\t${Version}\t${Architecture}\n',
                       'mkosi','qemu-system-x86','fdisk','debian-archive-keyring','curl','gpgv','systemd-boot',
                       'kmod','e2fsprogs'),
           'owners':('--search','/usr/bin/mkosi','/usr/bin/qemu-system-x86_64','/usr/sbin/sfdisk',
                     '/usr/share/keyrings/debian-archive-keyring.gpg','/usr/bin/gpgv','/usr/bin/curl',
                     '/usr/bin/bootctl'),
           'kmod_files':('--listfiles','kmod'),
           'e2fsprogs_files':('--listfiles','e2fsprogs'),
           'systemd_boot_files':('--listfiles','systemd-boot'),
           'depmod_usr_owner':('--search','/usr/sbin/depmod'),
           'depmod_sbin_owner':('--search','/sbin/depmod'),
           'mkfs_usr_owner':('--search','/usr/sbin/mkfs.ext4'),
           'mkfs_sbin_owner':('--search','/sbin/mkfs.ext4')}
    require(kind in table,'dpkg_kind');return ('/usr/bin/dpkg-query',)+table[kind]


def own_project_chown(project, phase, owner):
    require(type(owner) is str and re.fullmatch('[0-9]{1,6}:[0-9]{1,6}',owner),'owner_shape')
    if phase=='prepare':
        require(owner=='0:0','prepare_owner')
        return ('/usr/bin/sudo','-n','--','/usr/bin/chown','-R','--',owner,
                project_path(project,'extra'),project_path(project,'pkgmngr'))
    require(phase=='output' and owner!='0:0','chown_phase')
    return ('/usr/bin/sudo','-n','--','/usr/bin/chown','-R','--',owner,project_path(project,'out'))


def own_mkosi_outputs(project, uid, gid):
    # mkosi20.2 assigns staged non-directory outputs to INVOKING_USER.
    # Correct only the three QEMU inputs, never an output tree.
    require(type(uid) is int and type(gid) is int and 0<uid<1000000 and 0<gid<1000000,
            'mkosi_owner')
    owner=str(uid)+':'+str(gid)
    return ('/usr/bin/sudo','-n','--','/usr/bin/chown','--from='+owner,'--','0:0',
            *(project_path(project,'out/'+name) for name in
              ('ocv-test.raw','kernel.bin','initrd.img')))


def freeze_public_outputs(project):
    return ('/usr/bin/sudo','-n','--','/usr/bin/chmod','0444','--')+tuple(
        project_path(project,'out/'+name)for name in ('ocv-test.raw','kernel.bin','initrd.img'))


def python_tests(source_root,suite):
    require(suite in SUITES,'suite')
    return ('/usr/bin/python3','-I','-S','-B',project_path(source_root,'host/run_unit_tests.py'),'--suite',suite)


def ubuntu_sources():
    return (b'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble main universe\n'
            b'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu noble-updates main universe\n'
            b'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://security.ubuntu.com/ubuntu noble-security main universe\n')


if __name__=='__main__':raise SystemExit('inert_source_factories_only')
