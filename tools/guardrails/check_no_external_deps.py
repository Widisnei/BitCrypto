#!/usr/bin/env python3
import os, re, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]
FORBIDDEN = [
    r'#\s*include\s*<openssl[/\\]',
    r'#\s*include\s*<secp256k1[/\\]',
    r'#\s*include\s*<libbitcoin',
    r'#\s*include\s*<boost[/\\]',
    r'#\s*include\s*<fmt[/\\]',
    r'#\s*include\s*<spdlog[/\\]',
    r'#\s*include\s*<gmp[/\\]',
    r'find_package\s*\(',
]
bad=[]
for dp, dn, files in os.walk(ROOT):
    for f in files:
        if f.lower().endswith(('.h','.hpp','.hh','.cpp','.cc','.c','.cu','.cuh','.cmake','.txt','.yml','.yaml')):
            p = pathlib.Path(dp)/f
            t = p.read_text(encoding='utf-8', errors='ignore')
            if any(re.search(pat, t) for pat in FORBIDDEN):
                bad.append(str(p))
if not bad:
    print('Sem dependências externas proibidas'); sys.exit(0)
print('Encontradas dependências externas proibidas:'); [print(' ',b) for b in bad]; sys.exit(1)
