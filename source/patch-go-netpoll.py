from pathlib import Path
import hashlib
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: python patch-go-netpoll.py PATH_TO_GO_1.27.1_ROOT")
path = Path(sys.argv[1]) / "src/runtime/netpoll_epoll.go"
source = path.read_text(encoding="utf-8")
if "xd20WakeWriteFd" in source:
    print("XD20 local runtime patch already present")
    raise SystemExit(0)
backup = path.with_suffix(".go.official")
backup.write_bytes(path.read_bytes())
replacements = {
    "netpollWakeSig atomic.Uint32": "xd20WakeWriteFd uintptr // XD20: nonblocking pipe writer replaces unsupported eventfd\n\tnetpollWakeSig atomic.Uint32",
    "efd, errno := linux.Eventfd(0, linux.EFD_CLOEXEC|linux.EFD_NONBLOCK)\n\tif errno != 0 {\n\t\tprintln(\"runtime: eventfd failed with\", errno)":
    "efd, wfd, pipeErr := pipe2(_O_CLOEXEC | _O_NONBLOCK)\n\tif pipeErr != 0 {\n\t\tprintln(\"runtime: wake pipe failed with\", pipeErr)",
    "netpollEventFd = uintptr(efd)": "netpollEventFd = uintptr(efd)\n\txd20WakeWriteFd = uintptr(wfd)",
    "return fd == uintptr(epfd) || fd == netpollEventFd": "return fd == uintptr(epfd) || fd == netpollEventFd || fd == xd20WakeWriteFd",
    "n := write(netpollEventFd, noescape(unsafe.Pointer(&one)), oneSize)": "n := write(xd20WakeWriteFd, noescape(unsafe.Pointer(&one)), oneSize)",
}
for original, replacement in replacements.items():
    assert source.count(original) == 1, f"Unexpected official source fragment: {original[:35]}"
    source = source.replace(original, replacement)
path.write_text(source, encoding="utf-8", newline="\n")
print("Local ARM-compatible netpoll patch: unsupported eventfd replaced by nonblocking CLOEXEC pipe")
print("Original SHA256=" + hashlib.sha256(backup.read_bytes()).hexdigest())
