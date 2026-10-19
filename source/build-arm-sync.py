"""Build a minimal ARM Linux EABI5 sync helper (no external downloads).

ARM syscall ABI: r7=36 (sync), svc 0; r0=0, r7=1 (exit), svc 0.
No filesystem paths, dynamic loader, shell, or networking are used.
The equivalent C source is: int main(void) { sync(); return 0; }
"""
from pathlib import Path
import hashlib
import struct
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: python build-arm-sync.py NEW_OUTPUT_FILE")
out = Path(sys.argv[1])
if out.exists() or out.is_symlink():
    raise SystemExit("Output file already exists; refusing to replace it.")
base = 0x10000
header_size = 52 + 32
code = struct.pack("<5I", 0xE3A07024, 0xEF000000, 0xE3A00000, 0xE3A07001, 0xEF000000)
size = header_size + len(code)
ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + bytes(8)
ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, base + header_size,
                          52, 0, 0x05000000, 52, 32, 1, 0, 0, 0)
phdr = struct.pack("<8I", 1, 0, base, base, size, size, 5, 0x1000)
blob = ehdr + phdr + code
assert len(blob) == 104
out.write_bytes(blob)
print(f"ARM EABI5 sync helper: {len(blob)} bytes SHA256={hashlib.sha256(blob).hexdigest()}")
