"""Pure selector over observations. Collector must read kernel interfaces itself.
Not a runtime adapter and not a cryptographic attestation of the trusted kernel.
"""
import re
PROFILE='ubuntu-azure-7.0.0-1017.17-noble-backport-basepage-v1'
def select(o):
 def need(x,s):
  if not x:raise ValueError(s)
 need(o['uname_release']=='7.0.0-1017-azure','unsupported exact vendor release')
 need(re.fullmatch(r'Ubuntu 7[.]0[.]0-1017[.]17(?:~24[.]04[.]1)?-azure 7[.]0(?:[.][0-9]+)?',o['version_signature'].strip()),'unsupported Ubuntu build signature')
 need(o['architecture']=='x86_64' and o['page_size']==4096,'unsupported architecture/page geometry')
 need(o['mount_fs']=='tmpfs' and o['mount_magic']==0x01021994,'not tmpfs')
 need(o['fragment_size']==o['block_size']==4096,'statvfs geometry')
 need(0<o['blocks']*4096<=3221225472 and o['files']>0,'unbounded filesystem')
 need(o['available_blocks']==o['free_blocks'] and o['available_blocks']*4096>=1073741824,'actual reserve')
 opts=set(o['super_options'].split(','))
 need(not any(x.startswith(('huge=','usrquota','grpquota','quota','casefold')) for x in opts if x!='huge=never'),'unsupported mount extension')
 need(any(x in o['shmem_enabled'].split() for x in ['[deny]','[never]']),'unsupported global policy for non-mmap tmpfs writer')
 for path in o['per_size_shmem_controls']:
  need(re.fullmatch(r'/sys/kernel/mm/transparent_hugepage/hugepages-[0-9]+kB/shmem_enabled',path),'unknown per-size control shape')
  size=int(path.split('hugepages-')[1].split('kB')[0]);need(8<=size<=2048 and size&(size-1)==0,'unsupported shmem order geometry')
 lsms=set(o['active_lsms'].strip().split(','));need('capability' in lsms and lsms<={'capability','apparmor','yama','lockdown','landlock'},'unsupported active LSM initialization profile')
 need(o['default_acl_xattr'] is None,'default ACL inheritance unsupported')
 return {'profile':PROFILE,'regular_write_bound':'P*ceil(((offset%P)+length)/P)','symlink_bound_bytes':4096,'new_inode_units':1,'inode_units_exclude_hardlinks_and_xattrs':True,'runtime_match_is_not_execution_authorization':True}
