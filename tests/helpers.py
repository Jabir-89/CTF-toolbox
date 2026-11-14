"""Shared test helpers.

Scratch files go into ``tests/.scratch`` instead of the system temp directory so
the suite also runs inside restricted sandboxes that deny writes to temp paths.
"""
from __future__ import annotations

import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCRATCH_ROOT = Path(__file__).resolve().parent / ".scratch"


@contextmanager
def scratch() -> Iterator[Path]:
    """Yield an empty directory, then best-effort clean it up."""
    SCRATCH_ROOT.mkdir(exist_ok=True)
    workdir = SCRATCH_ROOT / uuid.uuid4().hex[:8]
    workdir.mkdir()
    try:
        yield workdir
    finally:
        for item in sorted(workdir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            try:
                item.unlink() if item.is_file() else item.rmdir()
            except OSError:
                pass
        try:
            workdir.rmdir()
        except OSError:
            pass
