import logging
from typing import Any

logger = logging.getLogger(__name__)


class WorkTracker:
    def __init__(self, helper: Any, name: str) -> None:
        self._helper = helper
        self._name = name
        self._work_api = None
        self._work_id = None
        self._connect_id = None
        self._init_work()

    def _init_work(self) -> None:
        api = getattr(self._helper, "api", None)
        if api is None:
            return
        work_api = getattr(api, "work", None)
        if work_api is None:
            return
        connect_id = getattr(self._helper, "connect_id", None) or getattr(self._helper, "connector_id", None)
        if not connect_id or not hasattr(work_api, "initiate_work"):
            self._work_api = work_api
            return
        try:
            self._work_id = work_api.initiate_work(connect_id, self._name)
            self._work_api = work_api
            self._connect_id = connect_id
        except Exception as exc:
            logger.debug("work_initiate_failed error=%s", exc)
            self._work_api = work_api
            self._connect_id = connect_id

    def log(self, message: str) -> None:
        if not self._work_api or not self._work_id:
            return
        if not hasattr(self._work_api, "add_log"):
            return
        try:
            self._work_api.add_log(self._work_id, message)
        except TypeError:
            try:
                self._work_api.add_log(self._work_id, message, "info")
            except Exception as exc:
                logger.debug("work_add_log_failed error=%s", exc)
        except Exception as exc:
            logger.debug("work_add_log_failed error=%s", exc)

    def progress(self, percent: int | None, message: str | None = None) -> None:
        if message:
            self.log(message)
        if percent is None or not self._work_api or not self._work_id:
            return
        bounded = max(0, min(100, int(percent)))
        if hasattr(self._work_api, "add_progress"):
            try:
                self._work_api.add_progress(self._work_id, bounded)
                return
            except Exception as exc:
                logger.debug("work_add_progress_failed error=%s", exc)
        if hasattr(self._work_api, "progress"):
            try:
                self._work_api.progress(self._work_id, bounded)
            except Exception as exc:
                logger.debug("work_progress_failed error=%s", exc)

    def done(self, message: str | None = None) -> None:
        if message:
            self.log(message)
        if not self._work_api or not self._work_id:
            return
        if hasattr(self._work_api, "to_processed"):
            try:
                self._work_api.to_processed(self._work_id, message or "Completed")
            except Exception as exc:
                logger.debug("work_complete_failed error=%s", exc)
