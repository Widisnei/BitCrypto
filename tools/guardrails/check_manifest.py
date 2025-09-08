#!/usr/bin/env python3
import os, sys, re, hashlib, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = next((p for p in ROOT.iterdir() if p.name.startswith('MANIFEST_') and p.suffix=='.txt'), None)
def sha256(p):
    h=hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1<<20), b''):
            h.update(chunk)
    return h.hexdigest()
if MANIFEST is None:
    print('Manifesto não encontrado'); sys.exit(2)
entries=[]
for ln in MANIFEST.read_text(encoding='utf-8', errors='ignore').splitlines():
    ln=ln.strip()
    if not ln or ln.startswith('SHA256'): continue
    parts = re.split(r'\s{2,}', ln)
    if len(parts)>=3:
        entries.append((parts[0], parts[1], parts[2]))
ok=True; listed=set()
for sh, sz, path in entries:
    fs = ROOT.parent/path
    if not fs.exists():
        print('[FALTA]', path); ok=False; continue
    b=fs.read_bytes(); sh2=sha256(fs); sz2=str(len(b))
    if sh2!=sh or sz2!=sz:
        print('[DIVERG]', path); ok=False
    listed.add(path)
for dp, dn, files in os.walk(ROOT):
    for f in files:
        rel = ('BitCrypto/'+str((pathlib.Path(dp)/f).relative_to(ROOT))).replace('\\','/')
        if rel not in listed and not rel.endswith('/.'):
            print('[EXTRA]', rel); ok=False
print('Manifesto OK' if ok else 'Manifesto divergente'); sys.exit(0 if ok else 1)
