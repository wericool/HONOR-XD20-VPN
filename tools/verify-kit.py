#!/usr/bin/env python3
"""Verify a downloaded public kit without installing or contacting the router."""
from pathlib import Path
import hashlib, re, sys

root=Path(__file__).resolve().parent.parent
manifest=root/'SHA256SUMS.txt'
count=0
for line in manifest.read_text(encoding='utf-8').splitlines():
    digest, name=line.split('  ',1)
    path=root/name
    if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise SystemExit('Unsafe manifest path')
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=digest:
        raise SystemExit('SHA256 mismatch: '+name)
    if path.suffix in {'.sh','.cgi'} or path.name=='S99xd20xray':
        if b'\r' in data or data.startswith(b'\xef\xbb\xbf'):
            raise SystemExit('Shell file contains CRLF/BOM: '+name)
    if path.name in {'xray.json','seed.json','httpd-private.conf','subscriptions.json','hwid','Sites.txt'}:
        raise SystemExit('Private runtime filename in manifest: '+name)
    count+=1
if (root/'domain.lst').read_text(encoding='utf-8').strip()!='example.com':
    raise SystemExit('Public domain template was changed')
print(f'Verified {count} public files. No router connection or installation performed.')
