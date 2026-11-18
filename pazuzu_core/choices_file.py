"""choices.json: what the wizard remembers on this device (the box's link, the block lists, the countries, the name
server, the steps done...). Several modules keep their part of it, and the wizard writes it from more than one thread
(a page's request, the manager starting, the box being told its step).

Every change goes through update(): under one lock, read, change, then written to a temporary file and moved into
place. A reader never sees a half-written file, and two writers never lose each other's change. Before (found 10 Nov
2026 by a test that failed now and then): each module read the file, changed its part and wrote the whole of it back
with no lock, and the write empties the file before it fills it, so a write from another thread at the wrong moment
read as "nothing saved" or put back an older copy over a choice saved a moment before."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Callable

NAME = "choices.json"
_LOCK = threading.RLock()


def read(key_dir) -> dict:
    """The whole of it, {} when there is none or it cannot be read."""
    with _LOCK:
        try:
            data = json.loads((Path(key_dir) / NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return data if isinstance(data, dict) else {}


def update(key_dir, change: Callable[[dict], object]) -> dict:
    """change(data) edits the dict in place; the result is written whole, atomically. Returns what was written."""
    with _LOCK:
        path = Path(key_dir) / NAME
        data = read(key_dir)
        change(data)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{NAME}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        for attempt in range(5):           # Windows refuses the move while another program has the file open for a moment
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 4:
                    try:
                        tmp.unlink()
                    except OSError:
                        pass
                    raise
                time.sleep(0.05)
        return data
