"""Сканирование сертификатов Windows и контейнеров КриптоПро."""
from __future__ import annotations

import ctypes
import os
import re
import stat
import threading
import time
import winreg
from ctypes import byref, create_unicode_buffer, wintypes
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import winapi
from .model import (
    Certificate,
    CertLocation,
    Container,
    STORE_DEFINITIONS,
    normalize_thumb,
    store_code,
)
from .tools import ToolRunner

KEY_WOW64_64KEY = winreg.KEY_WOW64_64KEY
KEY_WOW64_32KEY = winreg.KEY_WOW64_32KEY

HIVES = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKU": winreg.HKEY_USERS,
}

# Кэш результатов проверки отзыва: отпечаток -> (время, результат).
# Повторное сканирование не должно заново ждать CRL/OCSP.
_REVOCATION_CACHE: Dict[str, Tuple[float, Dict[str, object]]] = {}
_REVOCATION_CACHE_TTL = 3600.0


def _verify_revocation_bounded(cert_raw: bytes, timeout: float) -> Dict[str, object]:
    """Проверить отзыв, не блокируясь дольше timeout секунд.

    CertVerifyRevocation не умеет надёжно ограничивать время загрузки CRL
    (fCheckUrlRetrievalTimeout ломает проверку), поэтому вызов выполняется
    в отдельном потоке, а ожидание ограничивается снаружи.
    """
    box: Dict[str, object] = {}

    def worker() -> None:
        try:
            box["result"] = winapi.verify_revocation(cert_raw)
        except Exception as exc:  # защита от неожиданных сбоев API
            box["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(max(1.0, float(timeout)))
    if thread.is_alive():
        return {
            "status": "unknown",
            "reason": "",
            "message": "Проверка отзыва не завершилась за %.1f с" % timeout,
            "code": 0,
            "freshness": 0,
            "timeout": True,
        }
    error = box.get("error")
    if error is not None:
        return {
            "status": "unknown",
            "reason": "",
            "message": "Ошибка проверки отзыва: %s" % error,
            "code": 0,
            "freshness": 0,
        }
    result = box.get("result")
    if isinstance(result, dict):
        return result
    return {
        "status": "unknown",
        "reason": "",
        "message": "Проверка отзыва не дала результата",
        "code": 0,
        "freshness": 0,
    }

SKIP_DIR_NAMES = {
    "system volume information",
    "$recycle.bin",
    "recycler",
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "found.000",
    "config.msi",
    "$windows.~bt",
    "$windows.~ws",
    "perflogs",
    "recovery",
    "msocache",
}


class ScanCancelled(Exception):
    pass


@dataclass
class ScanResult:
    certificates: List[Certificate] = field(default_factory=list)
    containers: List[Container] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration: float = 0.0
    counts: Dict[str, int] = field(default_factory=dict)


def _safe_abspath(path: str) -> str:
    try:
        return os.path.abspath(path)
    except Exception:
        return path


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.normpath(_safe_abspath(path))).lower()


def _parse_date(value: str) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip().replace("/", ".")
    formats = (
        "%d.%m.%Y %H:%M:%S",
        "%d.%m.%Y %H:%M",
        "%d.%m.%Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    )
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_container_output(text: str) -> Dict[str, object]:
    """Извлечь отпечаток, CN и дату окончания из вывода certmgr -list -container."""
    result: Dict[str, object] = {
        "thumbprint": "",
        "subject": "",
        "not_after": None,
    }
    if not text:
        return result

    match = re.search(
        r"(?i)(?:thumbprint|отпечаток|hash|хеш)[^\r\n]*?([0-9a-f]{40})", text
    )
    if not match:
        match = re.search(r"\b([0-9a-fA-F]{40})\b", text)
    if match:
        result["thumbprint"] = normalize_thumb(match.group(1))

    cn_match = re.search(r"(?i)CN\s*=\s*([^,;\r\n]+)", text)
    if cn_match:
        cn = cn_match.group(1).strip().strip('"').replace('""', '"')
        result["subject"] = cn
    else:
        subj_match = re.search(r"(?i)(?:Subject|Субъект)\s*:\s*([^\r\n]+)", text)
        if subj_match:
            result["subject"] = subj_match.group(1).strip()

    date_match = re.search(
        r"(?i)(?:not valid after|valid to|истекает|действителен до|до)"
        r"[^\r\n]*?(\d{2}[./]\d{2}[./]\d{4})"
        r"(?:\s+(\d{1,2}:\d{2}:\d{2}))?",
        text,
    )
    if not date_match:
        date_match = re.search(
            r"\b(\d{2}[./]\d{2}[./]\d{4})(?:\s+(\d{1,2}:\d{2}:\d{2}))?\b",
            text,
        )
    if date_match:
        raw_date = date_match.group(1)
        raw_time = date_match.group(2) if date_match.lastindex and date_match.lastindex >= 2 else ""
        if raw_time:
            raw_date = raw_date + " " + raw_time
        result["not_after"] = _parse_date(raw_date)

    return result


class Scanner:
    def __init__(
        self,
        logger,
        tools: ToolRunner,
        cancel_event=None,
        progress: Optional[Callable[[str, int, int], None]] = None,
        check_revocation: bool = True,
        revocation_timeout: int = 3000,
        revocation_budget: float = 40.0,
    ) -> None:
        self.logger = logger
        self.tools = tools
        self.cancel_event = cancel_event
        self.progress = progress
        self.check_revocation = bool(check_revocation)
        self.revocation_timeout = max(500, int(revocation_timeout))
        self.revocation_budget = max(0.0, float(revocation_budget))
        self.current_sid = winapi.get_current_sid()
        self._scan_counter = 0
        self._scanned_roots: Set[str] = set()
        self.errors: List[str] = []
        self.container_map: Dict[str, List[str]] = {}
        self.container_to_thumb: Dict[str, str] = {}
        self._volume_cache: Dict[str, Tuple[str, str]] = {}

    # ------------------------------------------------------------------
    # Служебные
    # ------------------------------------------------------------------
    def _check_cancel(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ScanCancelled()

    def _report(self, text: str, current: int = 0, total: int = 0) -> None:
        if self.progress:
            try:
                self.progress(text, current, total)
            except Exception:
                pass

    def _error(self, message: str) -> None:
        self.errors.append(message)
        self.logger.warn(message)

    # ------------------------------------------------------------------
    # Полное сканирование
    # ------------------------------------------------------------------
    def scan_all(self) -> ScanResult:
        started = time.time()
        self.logger.info("Сканирование сертификатов Windows...")
        certificates = self.scan_certificates()
        if self.check_revocation:
            self.logger.info("Проверка отзыва сертификатов (CRL/OCSP)...")
            self._check_revocations(certificates)
        else:
            self.logger.info("Проверка отзыва отключена пользователем")
        self.logger.info("Сканирование контейнеров КриптоПро...")
        containers = self.scan_containers(certificates)
        self.logger.info("Сопоставление сертификатов и контейнеров...")
        self.link(certificates, containers)
        counts = self._counts(certificates, containers)
        duration = time.time() - started
        self.logger.info(
            "Сканирование завершено за %.1f сек. Сертификатов: %d, контейнеров: %d"
            % (duration, len(certificates), len(containers))
        )
        self.logger.info(
            "Просрочено: сертификатов %d, контейнеров %d; осиротевших контейнеров: %d"
            % (
                counts.get("cert_expired", 0),
                counts.get("cont_expired", 0),
                counts.get("cont_orphan", 0),
            )
        )
        if self.check_revocation:
            self.logger.info(
                "Отзыв: отозвано %d, не отозвано %d, неизвестно %d"
                % (
                    counts.get("cert_revoked", 0),
                    counts.get("cert_not_revoked", 0),
                    counts.get("cert_revocation_unknown", 0),
                )
            )
        return ScanResult(certificates, containers, list(self.errors), duration, counts)

    # ------------------------------------------------------------------
    # Сертификаты Windows
    # ------------------------------------------------------------------
    def scan_certificates(self) -> List[Certificate]:
        by_thumb: Dict[str, Certificate] = {}
        now = datetime.now()
        total = len(STORE_DEFINITIONS)
        for index, definition in enumerate(STORE_DEFINITIONS, start=1):
            self._check_cancel()
            self._report(
                "Чтение хранилища: %s" % definition["display"], index - 1, total
            )
            try:
                items = winapi.enum_certificates(
                    definition["store_name"], definition["location"]
                )
            except Exception as exc:
                self._error(
                    "Не удалось прочитать хранилище %s: %s"
                    % (definition["display"], exc)
                )
                continue
            self.logger.info(
                "Хранилище %s: найдено %d сертификатов"
                % (definition["display"], len(items))
            )
            for item in items:
                thumb = normalize_thumb(item.get("thumbprint", ""))
                if not thumb:
                    continue
                if thumb not in by_thumb:
                    not_after = item.get("not_after")
                    date_known = not_after is not None
                    is_expired = bool(date_known and not_after < now)
                    by_thumb[thumb] = Certificate(
                        thumbprint=thumb,
                        subject=item.get("subject", ""),
                        issuer=item.get("issuer", ""),
                        cn=item.get("cn", ""),
                        not_before=item.get("not_before"),
                        not_after=not_after,
                        date_known=date_known,
                        is_expired=is_expired,
                        has_private_key=bool(item.get("has_private_key")),
                        serial=item.get("serial", ""),
                        friendly_name=item.get("friendly_name", ""),
                        raw=item.get("raw", b""),
                        crl_urls=list(item.get("crl_urls", [])),
                        ocsp_urls=list(item.get("ocsp_urls", [])),
                        ca_issuer_urls=list(item.get("ca_issuer_urls", [])),
                    )
                cert = by_thumb[thumb]
                code = store_code(
                    definition["store_name"], definition["location"]
                )
                if code not in cert.store_codes:
                    cert.locations.append(
                        CertLocation(
                            store_name=definition["store_name"],
                            location=definition["location"],
                            display=definition["display"],
                            code=code,
                            has_private_key=bool(item.get("has_private_key")),
                        )
                    )
                if item.get("has_private_key"):
                    cert.has_private_key = True
                if not cert.raw and item.get("raw"):
                    cert.raw = item.get("raw", b"")

        certificates = list(by_thumb.values())
        for cert in certificates:
            cert.locations.sort(key=lambda loc: loc.display)
        certificates.sort(
            key=lambda c: (
                0 if c.is_expired else 1 if not c.date_known else 2,
                c.not_after or datetime.max,
                (c.cn or c.subject).lower(),
            )
        )
        self._report("Сертификаты Windows прочитаны", total, total)
        return certificates

    # ------------------------------------------------------------------
    # Проверка отзыва
    # ------------------------------------------------------------------
    def _check_revocations(self, certificates: List[Certificate]) -> None:
        """Проверить отзыв через CertVerifyRevocation.

        Проверяются только сертификаты, для которых есть DER-данные.
        Самоподписанные сертификаты пропускаются: у них нет внешнего CRL.
        Если CRL/OCSP недоступны, статус остаётся "unknown" — это честнее,
        чем считать сертификат действительным.
        """
        if not certificates:
            return

        # Сначала проверяем действующие сертификаты с ключом: именно они
        # важны для безопасного удаления. Просроченные — в конце.
        order = sorted(
            certificates,
            key=lambda c: (
                0
                if (c.date_known and not c.is_expired)
                else 1
                if not c.date_known
                else 2,
                0 if c.has_private_key else 1,
            ),
        )
        total = len(order)
        started = time.time()
        checked = 0
        for index, cert in enumerate(order, start=1):
            self._check_cancel()
            if cert.subject and cert.subject == cert.issuer:
                cert.revocation = "self_signed"
                cert.revocation_note = "Издатель совпадает с субъектом"
                continue
            if not cert.raw:
                cert.revocation = "unknown"
                cert.revocation_note = "Нет DER-данных сертификата"
                continue

            cached = _REVOCATION_CACHE.get(cert.thumbprint)
            if cached and (time.time() - cached[0]) < _REVOCATION_CACHE_TTL:
                result = cached[1]
            else:
                if (time.time() - started) > self.revocation_budget:
                    cert.revocation = "unknown"
                    cert.revocation_note = (
                        "Проверка пропущена: исчерпан лимит времени "
                        "(%.0f с)" % self.revocation_budget
                    )
                    continue
                self._report(
                    "Проверка отзыва: %s" % cert.display_name,
                    index - 1,
                    total,
                )
                result = _verify_revocation_bounded(
                    cert.raw, self.revocation_timeout / 1000.0
                )
                # Таймаут не кэшируем: при следующем сканировании имеет смысл
                # попробовать снова, если сеть уже доступна.
                if not result.get("timeout"):
                    _REVOCATION_CACHE[cert.thumbprint] = (time.time(), result)
                checked += 1

            cert.revocation = str(result.get("status") or "unknown")
            cert.revocation_reason = str(result.get("reason") or "")
            cert.revocation_note = str(result.get("message") or "")
            if cert.revocation == "revoked":
                self.logger.warn(
                    "Сертификат %s ОТОЗВАН (%s)"
                    % (cert.thumbprint, cert.revocation_reason or "причина неизвестна")
                )
            elif cert.revocation == "unknown":
                self.logger.debug(
                    "Сертификат %s: статус отзыва неизвестен (%s)"
                    % (cert.thumbprint, cert.revocation_note)
                )
        self._report("Проверка отзыва завершена", total, total)
        self.logger.info(
            "Проверка отзыва: выполнено запросов %d, сертификатов %d"
            % (checked, total)
        )

    # ------------------------------------------------------------------
    # Контейнеры
    # ------------------------------------------------------------------
    def scan_containers(self, certificates: List[Certificate]) -> List[Container]:
        containers: Dict[str, Container] = {}
        self.scan_container_map()
        self.scan_registry_containers(containers)
        self.scan_file_containers(containers)
        self.merge_csp_containers(containers)
        self.match_containers(certificates, containers)
        self.link(certificates, list(containers.values()))
        result = list(containers.values())
        kind_order = {"Registry": 0, "File": 1, "Unknown": 2}
        media_order = {"Registry": 0, "USB": 1, "HDD": 2, "Network": 3, "Unknown": 4}
        result.sort(
            key=lambda c: (
                kind_order.get(c.kind, 9),
                0 if c.is_problem else 1 if not c.info_known else 2,
                media_order.get(c.media, 9),
                (c.name or "").lower(),
            )
        )
        return result

    # -------------------------- реестр --------------------------------
    def scan_registry_containers(self, containers: Dict[str, Container]) -> None:
        roots = [
            ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Crypto Pro\Settings", KEY_WOW64_64KEY),
            ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Crypto Pro\Settings", KEY_WOW64_32KEY),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Crypto Pro\Settings", KEY_WOW64_64KEY),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Crypto Pro\Settings", KEY_WOW64_32KEY),
        ]
        found = 0
        for hive_name, hive, base_subkey, wow in roots:
            self._check_cancel()
            for keys_subkey in self._walk_for_keys(hive, base_subkey, wow, 4):
                self._check_cancel()
                for child in self._enum_subkeys(hive, keys_subkey, wow):
                    child_subkey = keys_subkey + "\\" + child
                    key = "REG:%s:%d:%s" % (hive_name, wow, child_subkey.lower())
                    if key in containers:
                        continue
                    display = hive_name + "\\" + child_subkey
                    if wow == KEY_WOW64_32KEY:
                        display += " [32-bit]"
                    containers[key] = Container(
                        key=key,
                        name=child,
                        kind="Registry",
                        media="Registry",
                        reg_path=display,
                        reg_hive=hive_name,
                        reg_subkey=child_subkey,
                        reg_wow64=wow,
                        full_name="REGISTRY\\" + child,
                        source="Реестр",
                    )
                    found += 1
        self.logger.info("Контейнеры в реестре Windows: %d" % found)

    def _walk_for_keys(
        self, hive, subkey: str, wow: int, depth: int
    ) -> Iterable[str]:
        if depth < 0:
            return
        last = subkey.split("\\")[-1].lower()
        if last == "keys":
            yield subkey
            return
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | wow) as key:
                index = 0
                while True:
                    try:
                        child = winreg.EnumKey(key, index)
                    except OSError:
                        break
                    index += 1
                    for item in self._walk_for_keys(
                        hive, subkey + "\\" + child, wow, depth - 1
                    ):
                        yield item
        except OSError:
            return

    def _enum_subkeys(self, hive, subkey: str, wow: int) -> List[str]:
        result: List[str] = []
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | wow) as key:
                index = 0
                while True:
                    try:
                        result.append(winreg.EnumKey(key, index))
                    except OSError:
                        break
                    index += 1
        except OSError:
            pass
        return result

    def _reg_key_exists(self, hive_name: str, subkey: str, wow: int) -> bool:
        hive = HIVES.get(hive_name)
        if hive is None:
            return False
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | wow):
                return True
        except OSError:
            return False

    # -------------------------- файлы ---------------------------------
    def scan_file_containers(self, containers: Dict[str, Container]) -> None:
        drives = winapi.get_logical_drives()
        self.logger.info("Логические диски: %s" % (", ".join(drives) or "нет"))
        for drive in drives:
            self._check_cancel()
            drive_type = winapi.get_drive_type(drive)
            if drive_type not in (2, 3):
                continue
            media = "USB" if drive_type == 2 else "HDD"
            self._report("Сканирование диска %s" % drive, 0, 0)
            known_roots = [
                os.path.join(drive, "var", "opt", "cryptopro"),
                os.path.join(drive, "Crypto Pro"),
                os.path.join(drive, "CryptoPro"),
                os.path.join(drive, "cryptopro"),
            ]
            for root in known_roots:
                self._scan_dir_for_containers(root, 4, containers, media)
            self._scan_dir_for_containers(drive, 1, containers, media)
            if drive_type == 2:
                self._scan_dir_for_containers(drive, 4, containers, media)
            else:
                self._scan_user_profiles(drive, containers, media)

        for env_name in ("LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "USERPROFILE"):
            base = os.environ.get(env_name, "")
            if base:
                self._scan_dir_for_containers(
                    os.path.join(base, "Crypto Pro"), 4, containers, "HDD"
                )
        user_profile = os.environ.get("USERPROFILE", "")
        if user_profile:
            self._scan_dir_for_containers(
                os.path.join(user_profile, "Documents", "Crypto Pro"),
                4,
                containers,
                "HDD",
            )
        self.logger.info(
            "Файловые контейнеры: %d"
            % sum(1 for c in containers.values() if c.kind == "File")
        )

    def _scan_user_profiles(
        self, drive: str, containers: Dict[str, Container], media: str
    ) -> None:
        users_dir = os.path.join(drive, "Users")
        if not os.path.isdir(users_dir):
            return
        try:
            entries = list(os.scandir(users_dir))
        except OSError:
            return
        for entry in entries:
            self._check_cancel()
            if not entry.is_dir(follow_symlinks=False):
                continue
            base = entry.path
            for relative in (
                os.path.join("AppData", "Local", "Crypto Pro"),
                os.path.join("AppData", "Roaming", "Crypto Pro"),
                "Crypto Pro",
                os.path.join("Documents", "Crypto Pro"),
            ):
                self._scan_dir_for_containers(
                    os.path.join(base, relative), 4, containers, media
                )

    def _scan_dir_for_containers(
        self,
        path: str,
        depth: int,
        containers: Dict[str, Container],
        media_hint: str,
    ) -> None:
        self._check_cancel()
        if not path or not os.path.isdir(path):
            return
        norm = _path_key(path)
        if norm in self._scanned_roots:
            return
        self._scanned_roots.add(norm)
        self._scan_counter += 1
        if self._scan_counter % 100 == 0:
            self._report("Сканирование: %s" % path, 0, 0)
        if self._is_container_dir(path):
            self._add_file_container(path, containers, media_hint)
            return
        if depth <= 0:
            return
        try:
            entries = list(os.scandir(path))
        except OSError:
            return
        for entry in entries:
            self._check_cancel()
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if entry.name.lower() in SKIP_DIR_NAMES:
                continue
            try:
                attrs = entry.stat(follow_symlinks=False).st_file_attributes
                if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
            except Exception:
                pass
            self._scan_dir_for_containers(
                entry.path, depth - 1, containers, media_hint
            )

    def _is_container_dir(self, path: str) -> bool:
        try:
            return os.path.isfile(os.path.join(path, "header.key"))
        except Exception:
            return False

    def _read_internal_name(self, path: str) -> str:
        """Прочитать имя контейнера из name.key (ASN.1, обычно cp1251)."""
        key_file = os.path.join(path, "name.key")
        try:
            with open(key_file, "rb") as fh:
                data = fh.read(4096)
        except Exception:
            return ""
        for index in range(max(0, len(data) - 2)):
            tag = data[index]
            if tag not in (0x0C, 0x13, 0x16):
                continue
            length = data[index + 1]
            if length <= 0 or length > len(data) - index - 2:
                continue
            chunk = data[index + 2 : index + 2 + length]
            for encoding in ("utf-8", "cp1251"):
                try:
                    text = chunk.decode(encoding).strip()
                except Exception:
                    continue
                if text and all(character >= " " for character in text):
                    return text
        return ""

    def _media_for_path(self, path: str) -> str:
        try:
            drive = os.path.splitdrive(_safe_abspath(path))[0]
            if not drive:
                return "Unknown"
            drive_type = winapi.get_drive_type(drive + "\\")
            return {
                2: "USB",
                3: "HDD",
                4: "Network",
            }.get(drive_type, "Unknown")
        except Exception:
            return "Unknown"

    def _add_file_container(
        self,
        path: str,
        containers: Dict[str, Container],
        media_hint: str,
    ) -> None:
        key = "FILE:" + _path_key(path)
        if key in containers:
            return
        media = media_hint or self._media_for_path(path)
        containers[key] = Container(
            key=key,
            name=os.path.basename(path.rstrip("\\/")) or path,
            kind="File",
            media=media,
            path=_safe_abspath(path),
            full_name=_safe_abspath(path),
            internal_name=self._read_internal_name(path),
            source="Файловая система",
        )

    # -------------------------- CSP -----------------------------------
    def _parse_csp_registry_name(
        self, raw: str
    ) -> Optional[Tuple[str, str, int]]:
        match = re.match(
            r"^\\\\\.\\REGISTRY\\(user|machine)\\(.+)$", raw.strip(), re.I
        )
        if not match:
            return None
        branch = match.group(1).lower()
        rest = match.group(2).strip("\\")
        if branch == "user":
            parts = rest.split("\\", 1)
            sid = parts[0]
            subkey = parts[1] if len(parts) > 1 else ""
            if not subkey:
                return None
            if self.current_sid and sid.upper() == self.current_sid.upper():
                hive_name = "HKCU"
                subkey = subkey
            else:
                hive_name = "HKU"
                subkey = rest
        else:
            hive_name = "HKLM"
            subkey = rest

        if "WOW6432NODE" in subkey.upper():
            wow = KEY_WOW64_64KEY
        elif self._reg_key_exists(hive_name, subkey, KEY_WOW64_64KEY):
            wow = KEY_WOW64_64KEY
        elif self._reg_key_exists(hive_name, subkey, KEY_WOW64_32KEY):
            wow = KEY_WOW64_32KEY
        else:
            wow = KEY_WOW64_64KEY
        return hive_name, subkey, wow

    def merge_csp_containers(self, containers: Dict[str, Container]) -> None:
        names = self.tools.enumerate_csp_containers()
        if not names:
            self.logger.warn(
                "csptest не вернул список контейнеров (или утилита недоступна)."
            )
            return
        self.logger.info("CSP-перечисление вернуло %d контейнеров" % len(names))
        for raw in names:
            self._check_cancel()
            upper = raw.upper()
            if "REGISTRY" in upper:
                parsed = self._parse_csp_registry_name(raw)
                if parsed:
                    hive_name, subkey, wow = parsed
                    existing = self._find_registry_container(
                        containers, hive_name, subkey
                    )
                    if existing is not None:
                        self._merge_container(existing, raw, "CSP")
                        continue
                    key = "REG:%s:%d:%s" % (hive_name, wow, subkey.lower())
                    display = hive_name + "\\" + subkey
                    if wow == KEY_WOW64_32KEY:
                        display += " [32-bit]"
                    containers[key] = Container(
                        key=key,
                        name=subkey.split("\\")[-1],
                        kind="Registry",
                        media="Registry",
                        reg_path=display,
                        reg_hive=hive_name,
                        reg_subkey=subkey,
                        reg_wow64=wow,
                        full_name=raw,
                        source="CSP",
                    )
                else:
                    short_name = re.sub(
                        r"(?i)^.*?REGISTRY\\+", "", raw
                    ).strip("\\")
                    existing = self._find_registry_container_by_name(
                        containers, short_name
                    )
                    if existing is not None:
                        self._merge_container(existing, raw, "CSP")
                        continue
                    key = "CSPREG:" + raw.lower()
                    if key in containers:
                        self._merge_container(containers[key], raw, "CSP")
                        continue
                    containers[key] = Container(
                        key=key,
                        name=short_name or raw.split("\\")[-1],
                        kind="Registry",
                        media="Registry",
                        full_name=raw,
                        source="CSP",
                    )
                continue

            path_match = re.search(r"([A-Za-z]:\\[^\r\n\"]*)", raw)
            if path_match:
                path = path_match.group(1).strip().strip('"')
                key = "FILE:" + _path_key(path)
                if key in containers:
                    self._merge_container(containers[key], raw, "CSP")
                    continue
                containers[key] = Container(
                    key=key,
                    name=os.path.basename(path.rstrip("\\/")) or path,
                    kind="File",
                    media=self._media_for_path(path),
                    path=_safe_abspath(path),
                    full_name=raw,
                    source="CSP",
                )
                continue

            key = "CSP:" + raw.lower()
            if key in containers:
                self._merge_container(containers[key], raw, "CSP")
                continue
            containers[key] = Container(
                key=key,
                name=raw,
                kind="Unknown",
                media="Unknown",
                full_name=raw,
                source="CSP",
            )

    def _find_registry_container(
        self,
        containers: Dict[str, Container],
        hive_name: str,
        subkey: str,
    ) -> Optional[Container]:
        target = subkey.lower()
        for container in containers.values():
            if container.kind != "Registry":
                continue
            if (
                container.reg_hive == hive_name
                and container.reg_subkey
                and container.reg_subkey.lower() == target
            ):
                return container
        return None

    def _find_registry_container_by_name(
        self, containers: Dict[str, Container], name: str
    ) -> Optional[Container]:
        target = (name or "").lower()
        if not target:
            return None
        for container in containers.values():
            if container.kind != "Registry":
                continue
            if (container.name or "").lower() == target:
                return container
        return None

    def _merge_container(
        self, container: Container, full_name: str, source: str
    ) -> None:
        if full_name and not container.full_name:
            container.full_name = full_name
        if source and source not in container.source:
            container.source = (container.source + " + " + source).strip(" +")

    # -------------------------- сопоставление --------------------------
    def scan_container_map(self) -> None:
        """Собрать карту «отпечаток -> имена контейнеров» из certmgr -list -store."""
        self.container_map = {}
        self.container_to_thumb = {}
        if not self.tools.certmgr:
            self.logger.warn(
                "certmgr.exe не найден: связь сертификатов с контейнерами недоступна."
            )
            return
        total = len(STORE_DEFINITIONS)
        for index, definition in enumerate(STORE_DEFINITIONS, start=1):
            self._check_cancel()
            self._report(
                "Чтение связей контейнеров: %s" % definition["display"],
                index - 1,
                total,
            )
            result = self.tools.run(
                [self.tools.certmgr, "-list", "-store", definition["code"]],
                timeout=45,
                log_output=False,
            )
            if result.timed_out or result.error:
                self.logger.warn(
                    "certmgr -list -store %s: %s"
                    % (definition["code"], result.error or "таймаут")
                )
                continue
            if not result.output:
                continue
            blocks = self._split_certmgr_blocks(result.output)
            found = 0
            for block in blocks:
                thumb_match = re.search(
                    r"(?i)(?:SHA1|отпечаток|thumbprint|hash)[^\r\n]*?([0-9a-f]{40})",
                    block,
                )
                if not thumb_match:
                    thumb_match = re.search(r"\b([0-9a-fA-F]{40})\b", block)
                if not thumb_match:
                    continue
                thumb = normalize_thumb(thumb_match.group(1))
                containers = re.findall(
                    r"(?im)^\s*(?:Контейнер|Container)\s*:\s*(.+?)\s*$",
                    block,
                )
                if containers:
                    self.container_map.setdefault(thumb, [])
                    for raw_name in containers:
                        name = self._normalize_container_name(raw_name)
                        if not name:
                            continue
                        if name not in self.container_map[thumb]:
                            self.container_map[thumb].append(name)
                        self.container_to_thumb[name.lower()] = thumb
                        found += 1
            if found:
                self.logger.debug(
                    "Хранилище %s: связей с контейнерами %d"
                    % (definition["display"], found)
                )
        self.logger.info(
            "Связей «сертификат — контейнер»: %d" % len(self.container_to_thumb)
        )

    def _split_certmgr_blocks(self, text: str) -> List[str]:
        blocks: List[str] = []
        current: List[str] = []
        for line in text.splitlines():
            if re.match(r"^\s*\d+-+\s*$", line):
                if current:
                    blocks.append("\n".join(current))
                current = []
            else:
                current.append(line)
        if current:
            blocks.append("\n".join(current))
        return blocks

    def _normalize_container_name(self, value: str) -> str:
        value = (value or "").strip().strip('"').strip()
        value = re.sub(r"(?i)^REGISTRY\\+", r"REGISTRY\\", value)
        return value.strip("\\")

    def _volume_info(self, path: str) -> Tuple[str, str]:
        try:
            drive = os.path.splitdrive(_safe_abspath(path))[0]
            if not drive:
                return "", ""
            root = drive + "\\"
            key = root.lower()
            if key in self._volume_cache:
                return self._volume_cache[key]
            volume_name = create_unicode_buffer(261)
            fs_name = create_unicode_buffer(261)
            serial = wintypes.DWORD()
            max_len = wintypes.DWORD()
            flags = wintypes.DWORD()
            ok = ctypes.windll.kernel32.GetVolumeInformationW(
                root,
                volume_name,
                261,
                byref(serial),
                byref(max_len),
                byref(flags),
                fs_name,
                261,
            )
            if ok:
                result = (fs_name.value or "", "%08X" % serial.value)
            else:
                result = ("", "")
            self._volume_cache[key] = result
            return result
        except Exception:
            return "", ""

    def _find_thumb_for_registry(self, container: Container) -> str:
        candidates = [
            container.name,
            "REGISTRY\\" + container.name,
            container.full_name or "",
            container.reg_path or "",
        ]
        for candidate in candidates:
            normalized = self._normalize_container_name(candidate)
            if normalized and normalized.lower() in self.container_to_thumb:
                return self.container_to_thumb[normalized.lower()]
        base = (container.name or "").lower()
        matches = set()
        for key, thumb in self.container_to_thumb.items():
            if key == base or key.endswith("\\" + base):
                matches.add(thumb)
        if len(matches) == 1:
            return next(iter(matches))
        return ""

    def _find_thumb_for_file(self, container: Container) -> str:
        path = container.path or ""
        if not path:
            return ""
        rel = ""
        try:
            drive = os.path.splitdrive(_safe_abspath(path))[0]
            rel = (
                os.path.relpath(path, drive + "\\")
                .replace("/", "\\")
                .strip("\\")
                .lower()
            )
        except Exception:
            rel = os.path.basename(path).lower()
        _fs, serial = self._volume_info(path)
        serial = serial.lower()
        if serial and rel:
            for key, thumb in self.container_to_thumb.items():
                if serial in key and ("\\" + rel) in key:
                    return thumb
        internal = self._normalize_container_name(
            container.internal_name or ""
        ).lower()
        if internal:
            for key, thumb in self.container_to_thumb.items():
                if key == internal or key.endswith("\\" + internal):
                    return thumb
        base = os.path.basename(path).lower()
        matches = set()
        for key, thumb in self.container_to_thumb.items():
            if (
                key == base
                or key.endswith("\\" + base)
                or ("\\" + base + "\\") in key
            ):
                matches.add(thumb)
        if len(matches) == 1:
            return next(iter(matches))
        return ""

    def match_containers(
        self, certificates: List[Certificate], containers: Dict[str, Container]
    ) -> None:
        by_thumb = {cert.thumbprint: cert for cert in certificates}
        items = list(containers.values())
        total = len(items)
        for index, container in enumerate(items, start=1):
            self._check_cancel()
            self._report(
                "Сопоставление контейнера %d из %d: %s"
                % (index, total, container.name),
                index - 1,
                total,
            )
            thumb = ""
            if container.kind == "Registry":
                thumb = self._find_thumb_for_registry(container)
            elif container.kind == "File":
                thumb = self._find_thumb_for_file(container)
            if thumb:
                container.thumbprint = thumb
                cert = by_thumb.get(thumb)
                if cert is not None:
                    container.subject = cert.cn or cert.subject or container.subject
                    container.not_after = cert.not_after
                    container.date_known = cert.date_known
                    container.is_expired = cert.is_expired
                    container.cert_found = True
                    container.orphan = False
                    container.info_known = True
                    container.note = ""
                    if container not in cert.containers:
                        cert.containers.append(container)
                else:
                    container.cert_found = False
                    container.orphan = False
                    container.info_known = True
                    container.note = "Сертификат не найден в хранилищах Windows"
            else:
                self._probe_container(container)
        self._report("Контейнеры сопоставлены", total, total)

    def _probe_container(self, container: Container) -> None:
        if not self.tools.csptest:
            container.info_known = False
            container.orphan = None
            container.note = "csptest.exe не найден"
            return
        variants: List[str] = []
        for value in (
            container.full_name,
            container.path,
            container.internal_name,
            container.name,
        ):
            if value and value not in variants:
                variants.append(value)
        if container.path:
            prefixed = "\\\\.\\" + container.path
            if prefixed not in variants:
                variants.append(prefixed)
        if container.kind == "Registry":
            reg_variant = "REGISTRY\\" + container.name
            if reg_variant not in variants:
                variants.append(reg_variant)
        elif container.kind == "File" and container.path:
            rel = ""
            try:
                drive = os.path.splitdrive(_safe_abspath(container.path))[0]
                rel = (
                    os.path.relpath(container.path, drive + "\\")
                    .replace("/", "\\")
                    .strip("\\")
                    .lower()
                )
            except Exception:
                rel = ""
            _fs, serial = self._volume_info(container.path)
            serial = serial.lower()
            if serial and rel:
                for key in self.container_to_thumb:
                    if serial in key and ("\\" + rel) in key and key not in variants:
                        variants.append(key)
        for variant in variants:
            self._check_cancel()
            result = self.tools.csptest_info_container(variant, timeout=8)
            text = (result.output or "").lower()
            if result.ok:
                container.info_known = True
                container.orphan = True
                container.note = "Сертификат не установлен в хранилищах Windows"
                return
            if "0x8009001a" in text:
                container.info_known = False
                container.orphan = None
                container.note = "Контейнер защищён паролем или недоступен"
                return
        container.info_known = False
        container.orphan = None
        container.note = "Не удалось проверить контейнер (csptest)"

    # -------------------------- сопоставление --------------------------
    def link(
        self, certificates: List[Certificate], containers: List[Container]
    ) -> None:
        by_thumb = {cert.thumbprint: cert for cert in certificates}
        for container in containers:
            if container.thumbprint:
                cert = by_thumb.get(container.thumbprint)
                if cert is not None:
                    container.certificate = cert
                    container.cert_found = True
                    container.orphan = False
                    container.info_known = True
                    container.subject = cert.cn or cert.subject or container.subject
                    container.not_after = cert.not_after
                    container.date_known = cert.date_known
                    container.is_expired = cert.is_expired
                    container.revocation = cert.revocation
                    container.revocation_reason = cert.revocation_reason
                    container.revocation_note = cert.revocation_note
                    if container not in cert.containers:
                        cert.containers.append(container)
                else:
                    container.cert_found = False
                    container.orphan = False
                    container.info_known = True
                    if not container.subject:
                        container.subject = container.thumbprint
                    note = "Сертификат не найден в хранилищах Windows"
                    container.note = (
                        (container.note + "; " + note) if container.note else note
                    )
            else:
                if container.info_known:
                    container.orphan = True
                else:
                    container.orphan = None

    # -------------------------- итоги ---------------------------------
    def _counts(
        self, certificates: List[Certificate], containers: List[Container]
    ) -> Dict[str, int]:
        return {
            "cert_total": len(certificates),
            "cert_expired": sum(1 for c in certificates if c.is_expired),
            "cert_unknown": sum(1 for c in certificates if not c.date_known),
            "cert_with_key": sum(1 for c in certificates if c.has_private_key),
            "cert_revoked": sum(1 for c in certificates if c.revocation == "revoked"),
            "cert_not_revoked": sum(1 for c in certificates if c.revocation == "good"),
            "cert_revocation_unknown": sum(
                1 for c in certificates if c.revocation == "unknown"
            ),
            "cert_revocation_not_checked": sum(
                1 for c in certificates if c.revocation == "not_checked"
            ),
            "cont_total": len(containers),
            "cont_registry": sum(1 for c in containers if c.kind == "Registry"),
            "cont_file": sum(1 for c in containers if c.kind == "File"),
            "cont_usb": sum(1 for c in containers if c.media == "USB"),
            "cont_expired": sum(1 for c in containers if c.is_expired),
            "cont_orphan": sum(1 for c in containers if c.orphan is True),
            "cont_unknown": sum(1 for c in containers if not c.info_known),
            "cont_revoked": sum(1 for c in containers if c.revocation == "revoked"),
        }
