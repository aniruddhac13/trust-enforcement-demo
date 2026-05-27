import json
from pathlib import Path
from threading import Lock
from typing import Any, Dict


class JsonStore:
    def __init__(self, path: Path, default_factory):
        self._path = Path(path)
        self._default_factory = default_factory
        self._lock = Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self.write(self._default_factory())

    def read(self) -> Dict[str, Any]:
        with self._lock:
            if not self._path.exists():
                self.write(self._default_factory())
            return json.loads(self._path.read_text(encoding="utf-8"))

    def write(self, value: Dict[str, Any]) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")

    def update(self, updater):
        with self._lock:
            data = self.read()
            updated = updater(data)
            self.write(updated)
            return updated
