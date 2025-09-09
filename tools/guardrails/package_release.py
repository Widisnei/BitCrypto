#!/usr/bin/env python3
# BitCrypto packaging script — robust single-root & residue-free
import os, sys, zipfile, hashlib, pathlib, subprocess, re

# Resolve project root: this script is at BitCrypto/tools/guardrails/
SCRIPT = pathlib.Path(__file__).resolve()
ROOT = SCRIPT.parents[2]           # .../BitCrypto
OUT_DIR = ROOT.parent

EXCLUDE_PATTERNS = [
    r'^MANIFEST_.*\.txt$',              # any manifest under project root
    r'^docs/AUDITORIA\.md$',            # legacy auditoria doc
    r'^tools/GUARDRAILS\.md$',          # legacy guardrails doc
    r'^\.git/',                         # diretório interno do Git
]

def sha256(p):
    h=hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1<<20), b''):
            h.update(chunk)
    return h.hexdigest()

def run(cmd):
    print('+', ' '.join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    print(r.stdout)
    if r.returncode!=0:
        print(r.stderr, file=sys.stderr); sys.exit(r.returncode)

def match_exclude(rel):
    for pat in EXCLUDE_PATTERNS:
        if re.search(pat, rel.replace('\\','/')):
            return True
    return False

def arcname_from(full: pathlib.Path, root: pathlib.Path) -> str:
    rel = str(full.relative_to(root)).replace('\\','/')
    # If rel already begins with "BitCrypto/", strip it to avoid double-root
    if rel.startswith('BitCrypto/'):
        rel = rel.split('BitCrypto/', 1)[1]
    return 'BitCrypto/' + rel

def main():
    version = sys.argv[1] if len(sys.argv)>1 else 'dev'

    # Guard-rails
    run([sys.executable, str(ROOT/'tools/guardrails/check_no_external_deps.py')])
    run([sys.executable, str(ROOT/'tools/guardrails/check_stubs.py')])
    run([sys.executable, str(ROOT/'tools/guardrails/check_features.py')])

    # Generate fresh MANIFEST in OUT_DIR
    manifest = OUT_DIR/f"MANIFEST_{version}.txt"
    with open(manifest, 'w', encoding='utf-8') as mf:
        mf.write('SHA256                           SIZE(bytes)  PATH\n')
        for dp, dn, files in os.walk(ROOT):
            for f in files:
                full = pathlib.Path(dp)/f
                rel = str(full.relative_to(ROOT)).replace('\\','/')
                if match_exclude(rel):
                    continue
                arc = arcname_from(full, ROOT)
                b = full.read_bytes()
                mf.write(f"{sha256(full)}  {len(b):10d}  {arc}\n")

    # Pack ZIP (residue-free)
    zip_path = OUT_DIR/f"BitCrypto-{version}.zip"
    if zip_path.exists(): zip_path.unlink()
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for dp, dn, files in os.walk(ROOT):
            for f in files:
                full = pathlib.Path(dp)/f
                rel = str(full.relative_to(ROOT)).replace('\\','/')
                if match_exclude(rel):
                    continue
                z.write(full, arcname=arcname_from(full, ROOT))
        # Add the new manifest at the end, under BitCrypto/
        z.write(manifest, arcname=f"BitCrypto/{manifest.name}")

    print('ZIP:', zip_path)
    print('SHA256:', sha256(zip_path))

if __name__=='__main__':
    main()
