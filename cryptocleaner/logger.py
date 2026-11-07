"""Журналирование CertCleaner."""
from __future__ import annotations

import os
import sys
import tempfile
import threading
from datetime import datetime
from typing import Callable, Optional, Tuple


LEVEL_ORDER = {
    "DEBUG": 10,
    "INFO": 20,
    "OK": 25,
    "WARN": 30,
    "ERROR": 40,
}


def _test_writable(directory: str) -> bool:
    try:
        os.makedirs(directory, exist_ok=True)
        probe = os.path.join(directory, ".cc_write_%s.tmp" % os.getpid())
        with open(probe, "w", encoding="ascii") as fh:
            fh.write("ok")
        os.remove(probe)
        return True
    except Exception:
        return False


def resolve_log_path(script_dir: str, explicit: str = "") -> Tuple[str, str]:
    """Вернуть (путь_к_логу, пояснение)."""
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = "log_%s.log" % stamp
    if explicit:
        directory = os.path.dirname(os.path.abspath(explicit))
        if _test_writable(directory):
            return explicit, ""
    if script_dir and _test_writable(script_dir):
        return os.path.join(script_dir, filename), ""
    temp = tempfile.gettempdir()
    if _test_writable(temp):
        return os.path.join(temp, filename), (
            "Папка скрипта недоступна для записи. Журнал сохранён в %s" % temp
        )
    return "", "Не удалось создать файл журнала."


class Logger:
    def __init__(
        self,
        path: str,
        ui_callback: Optional[Callable[[str, str], None]] = None,
        console: bool = False,
        level: str = "DEBUG",
        console_stream=None,
    ) -> None:
        self.path = path or ""
        self.ui_callback = ui_callback
        self.console = console
        self.level = level
        self.console_stream = console_stream or sys.stdout
        self._lock = threading.Lock()
        self._file_ok = False
        self._ensure_file()

    def _ensure_file(self) -> None:
        if not self.path:
            return
        try:
            directory = os.path.dirname(os.path.abspath(self.path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            new_file = not os.path.exists(self.path) or os.path.getsize(self.path) == 0
            with open(self.path, "a", encoding="utf-8") as fh:
                if new_file:
                    fh.write("\ufeff")
            self._file_ok = True
        except Exception:
            self._file_ok = False

    def set_ui_callback(self, callback: Optional[Callable[[str, str], None]]) -> None:
        self.ui_callback = callback

    def _write(self, level: str, message: str) -> str:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        line = "%s [%-5s] %s" % (stamp, level, message)
        if self._file_ok and self.path:
            try:
                with self._lock:
                    with open(self.path, "a", encoding="utf-8") as fh:
                        fh.write(line + "\r\n")
            except Exception:
                self._file_ok = False
        if self.console:
            try:
                print(line, file=self.console_stream, flush=True)
            except Exception:
                pass
        if self.ui_callback:
            try:
                self.ui_callback(level, line)
            except Exception:
                pass
        return line

    def _log(self, level: str, message: str) -> None:
        if LEVEL_ORDER.get(level, 0) < LEVEL_ORDER.get(self.level, 0):
            return
        self._write(level, str(message))

    def debug(self, message: str) -> None:
        self._log("DEBUG", message)

    def info(self, message: str) -> None:
        self._log("INFO", message)

    def ok(self, message: str) -> None:
        self._log("OK", message)

    def warn(self, message: str) -> None:
        self._log("WARN", message)

    def error(self, message: str) -> None:
        self._log("ERROR", message)

    def exception(self, message: str, exc: BaseException) -> None:
        self._log("ERROR", "%s: %s: %s" % (message, type(exc).__name__, exc))

    def close(self) -> None:
        self.info("Журнал закрыт.")
