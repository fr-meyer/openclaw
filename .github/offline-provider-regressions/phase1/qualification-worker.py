#!/usr/bin/env python3
import hashlib,importlib.util,json,os,pathlib,sys,argparse
HERE=pathlib.Path(__file__).resolve().parent
PINNED_PHASE1='2ada8587a4ab899591e2d9f6b758f8055e5a334bad2a8067a9d510e53a3a815e'
PINNED_PAYLOAD='1e60e7b485a0bead8c32732b0e81958ff6c0037465d991c9dd967a1cc5ed6f75'
def main():
 if hashlib.sha256((HERE/'phase1.py').read_bytes()).hexdigest()!=PINNED_PHASE1 or hashlib.sha256((HERE/'PAYLOAD-SHA256.json').read_bytes()).hexdigest()!=PINNED_PAYLOAD:raise RuntimeError('externally bound worker trusted entry/payload pin')
 manifest=json.loads((HERE/'worker-closure.json').read_text())
 for name,digest in manifest.items():
  p=HERE/name
  if p.is_symlink() or p.parent!=HERE or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise RuntimeError('trusted closure pin mismatch')
 spec=importlib.util.spec_from_file_location('trusted_phase1',HERE/'phase1.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 context=pathlib.Path(os.environ['OPENCLAW_CI_DOMAIN_CONTEXT']).resolve();cfg=json.loads((context/'worker-input.json').read_text())
 m.HERE=context/'tooling/.github/offline-provider-regressions/phase1';m.TOOLS=m.HERE.parent
 if hashlib.sha256((m.HERE/'PAYLOAD-SHA256.json').read_bytes()).hexdigest()!=PINNED_PAYLOAD:raise RuntimeError('tooling payload manifest pin')
 env=dict(os.environ);env.update(cfg['identity']);env.update(GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_NOSYSTEM='1',GIT_OPTIONAL_LOCKS='0')
 os.environ.clear();os.environ.update(env)
 a=argparse.Namespace(project=cfg['project'],candidate=str(context/'candidate'),carrier=str(context/'carrier'),work=str(context/'phase1-private'),artifacts=str(context/'receipts'))
 flow=m.Flow(a);flow.workerContext={'engineEnv':env,'context':str(context),'hostParent':cfg['hostParent']};flow.docker=cfg['docker'];flow.node=cfg['node']
 return flow.run()
if __name__=='__main__':sys.exit(main())
