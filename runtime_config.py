# runtime_config.py
from __future__ import annotations

import copy
import json
import os
import time
from typing import Any, Callable, Dict, Optional

from db import DB


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two dicts. override wins.
    """
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class RuntimeConfig:
    """
    Loads config from config.json + runtime overrides from DB.settings(runtime).
    Auto-detects changes using:
      - file mtime
      - settings.updated_ts
    """

    def __init__(
        self,
        db: DB,
        file_path: str = "config.json",
        poll_sec: float = 2.0,
    ) -> None:
        self.db = db
        self.file_path = file_path
        self.poll_sec = float(poll_sec)

        self._last_file_mtime: float = 0.0
        self._last_runtime_ts: int = 0

        self._cfg: Dict[str, Any] = {}
        self._last_refresh_ts: float = 0.0

        self.refresh(force=True)

    def _read_file_cfg(self) -> Dict[str, Any]:
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception:
            return {}

    def refresh(self, force: bool = False) -> bool:
        """
        Returns True if config changed.
        """
        changed = False

        try:
            mtime = os.path.getmtime(self.file_path)
        except OSError:
            mtime = 0.0

        runtime_ts = self.db.get_settings_updated_ts("runtime") or 0

        if force or (mtime != self._last_file_mtime) or (runtime_ts != self._last_runtime_ts):
            self._last_file_mtime = mtime
            self._last_runtime_ts = runtime_ts

            file_cfg = self._read_file_cfg()
            runtime_cfg = self.db.get_settings_dict() or {}

            # runtime wins over file
            self._cfg = deep_merge(file_cfg, runtime_cfg)
            changed = True

        self._last_refresh_ts = time.time()
        return changed

    def snapshot(self) -> Dict[str, Any]:
        """
        Safe snapshot (deepcopy) for use in async code.
        """
        return copy.deepcopy(self._cfg)

    async def loop(self, on_change: Optional[Callable[[Dict[str, Any]], Any]] = None) -> None:
        """
        Periodic refresh loop; if changed -> calls on_change(cfg_snapshot)
        """
        import asyncio

        while True:
            try:
                if self.refresh(force=False) and on_change:
                    cfg = self.snapshot()
                    res = on_change(cfg)
                    if asyncio.iscoroutine(res):
                        await res
            except Exception:
                pass
            await asyncio.sleep(self.poll_sec)

    @property
    def last_runtime_ts(self) -> int:
        return int(self._last_runtime_ts)

    @property
    def last_file_mtime(self) -> float:
        return float(self._last_file_mtime)
