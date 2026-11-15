import hashlib,json,pathlib,sys
m=json.loads(pathlib.Path(__file__).with_name('b-manifest.json').read_text())
root=pathlib.Path(sys.argv[1])
for p,h in {**m['sourcePins'],'pnpm-lock.yaml':m['lockSha256']}.items():
    if hashlib.sha256((root/p).read_bytes()).hexdigest()!=h: raise SystemExit('source drift: '+p)
p=json.loads((root/'package.json').read_text())
if p['packageManager']!='pnpm@12.9.0+sha512.8f64efa0b792986ca98ae568791bcd7722807e274c4f0c1d9853c62116495c584119db98762a2a5343b1684d361b9ae26fdd16d551666d7635346d3fae830ddd': raise SystemExit('package manager drift')
