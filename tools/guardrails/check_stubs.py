#!/usr/bin/env python3
import os, re, pathlib, sys
ROOT = pathlib.Path(__file__).resolve().parents[2]
TOKENS = [r'\bTODO\b', r'\bFIXME\b', r'NOT IMPLEMENTED', r'UNIMPLEMENTED', r'\bstub\b', r'assert\s*\(\s*false\s*\)']
bad=[]
for dp, dn, files in os.walk(ROOT):
    for f in files:
        if f.lower().endswith(('.h','.hpp','.hh','.cpp','.cc','.c','.cu','.cuh','.cmake','.yml','.yaml')) and '/docs/' not in str(pathlib.Path(dp)/f).replace('\\','/'):
            p = pathlib.Path(dp)/f
            t = p.read_text(encoding='utf-8', errors='ignore')
            if any(re.search(pat, t) for pat in TOKENS):
                bad.append(str(p))
if not bad:
    print('Sem stubs/TODO/FIXME'); sys.exit(0)
print('Encontrados stubs/TODO/FIXME:'); [print(' ',b) for b in bad]; sys.exit(1)
