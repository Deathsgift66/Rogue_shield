"""Local file primitives: no network or subprocess dependencies.

Outputs are created atomically with private permissions and never overwrite an
existing file. Inputs must be ordinary files (not devices, FIFOs or symlinks).
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

MAX_JSON_BYTES = 1_000_000


def read_regular(path: str | Path, *, max_bytes: int = MAX_JSON_BYTES) -> bytes:
    p = Path(path)
    if p.is_symlink():
        raise ValueError("Symbolic-link inputs are not allowed")
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(p, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise ValueError('Input is not an allowed regular file, or exceeds the size budget')
        payload = bytearray()
        while len(payload) <= max_bytes:
            block = os.read(fd, min(65536, max_bytes + 1 - len(payload)))
            if not block:
                break
            payload.extend(block)
        if len(payload) > max_bytes:
            raise ValueError('File size exceeds the input budget')
        return bytes(payload)
    finally:
        os.close(fd)


def create_private(path: str | Path, content: str) -> None:
    p = Path(path)
    if not p.parent.is_dir() or p.parent.is_symlink():
        raise ValueError('Output folder is unavailable or a symbolic link')
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as dest:
            dest.write(content)
    except BaseException:
        # An incomplete private report must not be mistaken for a completed scan.
        p.unlink(missing_ok=True)
        raise
