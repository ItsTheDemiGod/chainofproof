"""Cross-process (and cross-thread) exclusive lock using only the stdlib."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

_thread_locks: dict[str, threading.Lock] = {}
_registry_lock = threading.Lock()

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


def _thread_lock(path: Path) -> threading.Lock:
    with _registry_lock:
        return _thread_locks.setdefault(str(path), threading.Lock())


class FileLock:
    """Exclusive lock on a lock file: threading.Lock in-process, msvcrt/fcntl across processes."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._tlock = _thread_lock(self.path)
        self._fh = None

    def __enter__(self) -> FileLock:
        self._tlock.acquire()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a+b")
            if self._fh.seek(0, 2) == 0:
                self._fh.write(b"0")
                self._fh.flush()
            self._fh.seek(0)
            if sys.platform == "win32":
                while True:
                    try:
                        msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        time.sleep(0.005)
            else:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except BaseException:
            self._release()
            raise
        return self

    def _release(self) -> None:
        if self._fh is not None:
            self._fh.close()  # closing the handle drops the OS lock
            self._fh = None
        self._tlock.release()

    def __exit__(self, *exc: object) -> None:
        if self._fh is not None and sys.platform == "win32":
            self._fh.seek(0)
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        self._release()
