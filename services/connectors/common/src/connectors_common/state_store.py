import json
import os
from typing import Any


class StateStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self.state = self._load()

    def _load(self) -> dict[str, Any]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def get(self, key: str, default: Any = None) -> Any:
        return self.state.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.state[key] = value
        self._save()

    def remember_hash(self, namespace: str, value: str, max_items: int = 5000) -> bool:
        key = f"hashes:{namespace}"
        hashes = self.state.get(key, [])
        if value in hashes:
            return False
        hashes.append(value)
        if len(hashes) > max_items:
            hashes = hashes[-max_items:]
        self.state[key] = hashes
        self._save()
        return True

    def _save(self) -> None:
        tmp_path = f"{self.path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(self.state, handle, indent=2)
        os.replace(tmp_path, self.path)
