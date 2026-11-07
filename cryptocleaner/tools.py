"""Запуск внешних утилит КриптоПро и Windows."""
from __future__ import annotations

import ctypes
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from . import winapi

CREATE_NO_WINDOW = 0x08000000
KEY_WOW64_64KEY = 0x0100
KEY_WOW64_32KEY = 0x0200


def _oem_encoding() -> str:
    try:
        cp = int(ctypes.windll.kernel32.GetOEMCP())
        if cp > 0:
            return "cp%d" % cp
    except Exception:
        pass
    return "cp866"


def decode_output(data: bytes) -> str:
    if not data:
        return ""
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    for enc in (_oem_encoding(), "cp866", "cp1251", "utf-8"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("latin-1", errors="replace")


def quote_arg(value: str) -> str:
    value = str(value)
    if not value:
        return '""'
    if re.search(r'[\s"]', value):
        return '"' + value.replace('"', '\\"') + '"'
    return value


def format_command(args: Sequence[str], sensitive: bool = False) -> str:
    parts = [quote_arg(a) for a in args]
    text = " ".join(parts)
    if sensitive:
        text = re.sub(
            r"(?i)(\s-(?:p|password|pin)\s+)(\"[^\"]*\"|\S+)",
            r"\1***",
            text,
        )
    return text


def _read_reg_value(root, subkey: str, names: Iterable[str], wow64: int) -> List[str]:
    import winreg

    values: List[str] = []
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | wow64) as key:
            for name in names:
                try:
                    value, _ = winreg.QueryValueEx(key, name)
                    if isinstance(value, str) and value.strip():
                        values.append(value.strip())
                except OSError:
                    pass
            try:
                value, _ = winreg.QueryValueEx(key, "")
                if isinstance(value, str) and value.strip():
                    values.append(value.strip())
            except OSError:
                pass
    except OSError:
        pass
    return values


def find_cryptopro() -> Dict[str, str]:
    """Найти каталог Crypto Pro CSP, certmgr.exe и csptest.exe."""
    import winreg

    candidates: List[str] = []
    for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(env_name, "")
        if base:
            candidates.append(os.path.join(base, "Crypto Pro", "CSP"))
            candidates.append(os.path.join(base, "Crypto Pro", "CSP", "bin"))

    value_names = ("InstallDir", "Path", "InstallPath", "CSPDir", "InstallLocation")
    reg_roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Crypto Pro\CSP", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Crypto Pro\CSP", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Crypto Pro\CSP", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_CURRENT_USER, r"Software\Crypto Pro\CSP", winreg.KEY_WOW64_64KEY),
    ]
    for root, subkey, wow in reg_roots:
        for value in _read_reg_value(root, subkey, value_names, wow):
            candidates.append(value)
            candidates.append(os.path.join(value, "CSP"))

    for exe in ("certmgr.exe", "csptest.exe"):
        found = shutil.which(exe)
        if found:
            candidates.append(os.path.dirname(found))

    # Частые варианты установки
    for base in (
        r"C:\Program Files\Crypto Pro\CSP",
        r"C:\Program Files (x86)\Crypto Pro\CSP",
        r"C:\Program Files\Crypto Pro\CSP\bin",
        r"C:\Program Files (x86)\Crypto Pro\CSP\bin",
    ):
        candidates.append(base)

    certmgr = ""
    csptest = ""
    csp_dir = ""
    seen = set()
    for directory in candidates:
        if not directory:
            continue
        norm = os.path.normpath(directory)
        if norm.lower() in seen:
            continue
        seen.add(norm.lower())
        cm = os.path.join(norm, "certmgr.exe")
        ct = os.path.join(norm, "csptest.exe")
        if not certmgr and os.path.exists(cm):
            certmgr = cm
            csp_dir = norm
        if not csptest and os.path.exists(ct):
            csptest = ct
            if not csp_dir:
                csp_dir = norm
    return {"dir": csp_dir, "certmgr": certmgr, "csptest": csptest}


@dataclass
class ToolResult:
    args: List[str]
    exit_code: int
    output: str
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error

    @property
    def command(self) -> str:
        return format_command(self.args)


class ToolRunner:
    def __init__(self, logger, cancel_event=None) -> None:
        self.logger = logger
        self.cancel_event = cancel_event
        self.paths = find_cryptopro()
        self.certmgr = self.paths.get("certmgr", "")
        self.csptest = self.paths.get("csptest", "")
        self.csp_dir = self.paths.get("dir", "")
        self.certutil = winapi.system_tool("certutil.exe")
        self.reg = winapi.system_tool("reg.exe")
        self._container_cache: Dict[str, ToolResult] = {}

    def log_environment(self) -> None:
        self.logger.info("Каталог Crypto Pro CSP: %s" % (self.csp_dir or "не найден"))
        self.logger.info("certmgr.exe: %s" % (self.certmgr or "не найден"))
        self.logger.info("csptest.exe: %s" % (self.csptest or "не найден"))
        self.logger.info("certutil.exe: %s" % self.certutil)
        self.logger.info("reg.exe: %s" % self.reg)
        if not self.certmgr:
            self.logger.warn(
                "certmgr.exe не найден. Сертификаты Windows доступны, "
                "но информация о контейнерах и их удаление через КриптоПро могут быть недоступны."
            )

    def run(
        self,
        args: Sequence[str],
        timeout: int = 60,
        sensitive: bool = False,
        log_output: bool = True,
    ) -> ToolResult:
        args = [str(a) for a in args]
        if self.cancel_event is not None and self.cancel_event.is_set():
            return ToolResult(args, -1, "", error="Отменено пользователем")
        display = format_command(args, sensitive=sensitive)
        self.logger.debug("Запуск: %s" % display)
        try:
            completed = subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=max(1, int(timeout)),
                creationflags=CREATE_NO_WINDOW,
            )
            output = decode_output(completed.stdout or b"")
            result = ToolResult(args, int(completed.returncode), output)
        except subprocess.TimeoutExpired as exc:
            raw = exc.stdout or b""
            output = decode_output(raw)
            result = ToolResult(args, -1, output, timed_out=True, error="Таймаут выполнения")
        except FileNotFoundError:
            result = ToolResult(args, -1, "", error="Файл не найден")
        except Exception as exc:
            result = ToolResult(args, -1, "", error="%s: %s" % (type(exc).__name__, exc))
        if result.timed_out:
            self.logger.warn("Таймаут: %s" % display)
        elif result.error:
            self.logger.warn("Ошибка запуска %s: %s" % (display, result.error))
        elif result.exit_code != 0:
            self.logger.debug("Код возврата %s: %s" % (result.exit_code, display))
        if log_output and result.output.strip():
            text = result.output.strip()
            if len(text) > 4000:
                text = text[:4000] + "\n... (вывод обрезан)"
            self.logger.debug("Вывод:\n%s" % text)
        return result

    def certmgr_list_container(self, name: str, timeout: int = 20) -> ToolResult:
        key = (name or "").lower()
        if key in self._container_cache:
            return self._container_cache[key]
        if not self.certmgr:
            result = ToolResult([], -1, "", error="certmgr.exe не найден")
        else:
            result = self.run(
                [self.certmgr, "-list", "-container", name],
                timeout=timeout,
                log_output=True,
            )
        self._container_cache[key] = result
        return result

    def enumerate_csp_containers(self, timeout: int = 40) -> List[str]:
        if not self.csptest:
            return []
        result = self.run(
            [self.csptest, "-keyset", "-enum_containers", "-fqcn", "-silent"],
            timeout=timeout,
            log_output=True,
        )
        if result.error or result.timed_out:
            return []
        names: List[str] = []
        seen = set()
        for raw_line in result.output.splitlines():
            line = raw_line.strip().strip('"').strip()
            if not line:
                continue
            low = line.lower()
            if low.startswith(("csptest", "total", "error", "ошибка", "csp ", "[errorcode")):
                continue
            if low.startswith(("container", "контейнер")):
                # Иногда строка имеет вид "Container: \\.\..."
                if ":" in line:
                    candidate = line.split(":", 1)[1].strip().strip('"')
                    if candidate and candidate not in seen:
                        seen.add(candidate)
                        names.append(candidate)
                continue
            if "\\\\.\\" in line or re.search(r"[A-Za-z]:\\", line) or "REGISTRY" in line.upper():
                if line not in seen:
                    seen.add(line)
                    names.append(line)
        return names

    def csptest_info_container(self, name: str, timeout: int = 8) -> ToolResult:
        if not self.csptest:
            return ToolResult([], -1, "", error="csptest.exe не найден")
        return self.run(
            [
                self.csptest,
                "-keyset",
                "-info",
                "-container",
                name,
                "-silent",
            ],
            timeout=timeout,
            log_output=True,
        )

    def reg_export(self, reg_path: str, file_path: str, wow64: int = 0, timeout: int = 60) -> ToolResult:
        args = [self.reg, "export", reg_path, file_path, "/y"]
        if wow64 == KEY_WOW64_32KEY:
            args.append("/reg:32")
        elif wow64 == KEY_WOW64_64KEY:
            args.append("/reg:64")
        return self.run(args, timeout=timeout, log_output=False)
