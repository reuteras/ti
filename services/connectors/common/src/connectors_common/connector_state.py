import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _load_state(helper: Any) -> dict[str, Any]:
    if not helper or not hasattr(helper, "get_state"):
        return {}
    try:
        state = helper.get_state()
    except Exception as exc:
        logger.debug("connector_state_get_failed error=%s", exc)
        return {}
    return state if isinstance(state, dict) else {}


def _save_state(helper: Any, state: dict[str, Any]) -> None:
    if not helper or not hasattr(helper, "set_state"):
        return
    try:
        helper.set_state(state)
    except Exception as exc:
        logger.debug("connector_state_set_failed error=%s", exc)


class ConnectorState:
    def __init__(self, helper: Any, name: str) -> None:
        self._helper = helper
        self._name = name
        self._start: datetime | None = None
        self._metrics: dict[str, Any] = {}

    def start(self) -> None:
        self._start = datetime.now(timezone.utc)
        state = _load_state(self._helper)
        state.update(
            {
                "connector": self._name,
                "status": "running",
                "last_start": self._start.isoformat(),
            }
        )
        _save_state(self._helper, state)

    def update(self, **metrics: Any) -> None:
        for key, value in metrics.items():
            if value is None:
                continue
            self._metrics[key] = value

    def success(self, **metrics: Any) -> None:
        self.update(**metrics)
        self._finalize(status="success", clear_error=True)

    def failure(self, error: str | None = None, **metrics: Any) -> None:
        self.update(**metrics)
        self._finalize(status="failed", error=error)

    def skipped(self, reason: str | None = None, **metrics: Any) -> None:
        if reason:
            self.update(skip_reason=reason)
        self.update(**metrics)
        self._finalize(status="skipped", clear_error=True)

    def _finalize(self, status: str, error: str | None = None, clear_error: bool = False) -> None:
        end = datetime.now(timezone.utc)
        state = _load_state(self._helper)
        if self._metrics:
            state.update(self._metrics)
        state["status"] = status
        state["last_run"] = end.isoformat()
        if self._start:
            state["duration_seconds"] = int((end - self._start).total_seconds())
        if status == "success":
            state["last_success"] = end.isoformat()
        if clear_error:
            state.pop("last_error", None)
            state.pop("last_error_at", None)
        if error:
            trimmed = error.strip().replace("\n", " ")
            state["last_error"] = trimmed[:500]
            state["last_error_at"] = end.isoformat()
        _save_state(self._helper, state)
