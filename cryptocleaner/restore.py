"""Чтение резервных копий CryptoCleaner и восстановление выбранных объектов.

Поддерживаются новые одиночные архивы ``*.ccbackup`` и старые резервные
копии в виде каталога (для совместимости). Восстановление всегда проверяет
результат повторным чтением хранилища, каталога или ветки реестра: ошибка
доступа или невозможность проверки не считаются успехом.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import tempfile
import winreg
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from . import winapi
from .backup import pfx_has_private_key
from .model import (
    OperationResult,
    STORE_DEFINITIONS,
    format_dt,
    normalize_thumb,
    safe_filename,
)
from .scanner import HIVES
from .tools import KEY_WOW64_32KEY, KEY_WOW64_64KEY, ToolRunner

BACKUP_EXTENSION = ".ccbackup"
DEFAULT_LOCATION = {
    "store_name": "My",
    "location": "CurrentUser",
    "display": "Личные (Пользователь)",
    "code": "uMy",
}


class RestoreError(Exception):
    pass


class RestoreCancelled(Exception):
    pass


def _parse_iso(value: str) -> Optional[datetime]:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        pass
    for fmt in ("%d.%m.%Y %H:%M:%S", "%d.%m.%Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _format_size(value: int) -> str:
    if value >= 1024 * 1024 * 1024:
        return "%.1f ГБ" % (value / (1024.0 ** 3))
    if value >= 1024 * 1024:
        return "%.1f МБ" % (value / (1024.0 ** 2))
    if value >= 1024:
        return "%.0f КБ" % (value / 1024.0)
    return "%d Б" % value


def _parse_locations(value: str) -> List[Dict[str, str]]:
    value = (value or "").strip()
    if not value or value == "—":
        return [dict(DEFAULT_LOCATION)]
    displays = [part.strip() for part in value.split(";") if part.strip()]
    by_display = {item["display"]: item for item in STORE_DEFINITIONS}
    result: List[Dict[str, str]] = []
    for display in displays:
        item = by_display.get(display)
        if item is None:
            lowered = display.lower()
            if "пользовател" in lowered:
                location = "CurrentUser"
            elif "компьютер" in lowered:
                location = "LocalMachine"
            else:
                location = "CurrentUser"
            if "промежуточ" in lowered:
                store_name = "CA"
            elif "доверен" in lowered:
                store_name = "Root"
            else:
                store_name = "My"
            code = ("u" if location == "CurrentUser" else "m") + {
                "My": "My",
                "CA": "CA",
                "Root": "ROOT",
            }[store_name]
            item = {
                "store_name": store_name,
                "location": location,
                "display": display,
                "code": code,
            }
        entry = {
            "store_name": item["store_name"],
            "location": item["location"],
            "display": item["display"],
            "code": item["code"],
        }
        if entry not in result:
            result.append(entry)
    return result or [dict(DEFAULT_LOCATION)]


def _parse_reg_path(reg_path: str) -> Tuple[str, str, int]:
    value = (reg_path or "").strip()
    wow = 0
    if value.lower().endswith(" [32-bit]"):
        value = value[: -len(" [32-bit]")]
        wow = KEY_WOW64_32KEY
    elif value.lower().endswith(" [64-bit]"):
        value = value[: -len(" [64-bit]")]
        wow = KEY_WOW64_64KEY
    if "\\" not in value:
        return "", value, wow
    hive, subkey = value.split("\\", 1)
    return hive.strip().upper(), subkey.strip("\\"), wow


@dataclass
class RestoreCertificate:
    thumbprint: str
    name: str
    subject: str = ""
    issuer: str = ""
    not_after: Optional[datetime] = None
    has_private_key: bool = False
    saved: bool = True
    files: List[str] = field(default_factory=list)
    cer: str = ""
    pfx: str = ""
    pfx_has_key: Optional[bool] = None
    locations: List[Dict[str, str]] = field(default_factory=list)
    containers: List[str] = field(default_factory=list)
    note: str = ""

    @property
    def location_display(self) -> str:
        return "; ".join(item["display"] for item in self.locations) or "—"

    @property
    def key_display(self) -> str:
        if not self.has_private_key:
            return "нет"
        if self.pfx_has_key:
            return "PFX с ключом"
        return "ключ в контейнере"

    @property
    def status_display(self) -> str:
        return "сохранён" if self.saved else "ошибка"


@dataclass
class RestoreContainer:
    key: str
    name: str
    kind: str = "Unknown"
    media: str = ""
    path: str = ""
    reg_path: str = ""
    reg_hive: str = ""
    reg_subkey: str = ""
    reg_wow64: int = 0
    full_name: str = ""
    internal_name: str = ""
    thumbprint: str = ""
    subject: str = ""
    not_after: Optional[datetime] = None
    saved: bool = True
    files: List[str] = field(default_factory=list)
    dir_entry: str = ""
    pfx_entry: str = ""
    reg_entry: str = ""
    note: str = ""

    @property
    def kind_display(self) -> str:
        return {
            "Registry": "Реестр",
            "File": "Файл",
            "Unknown": "Неизвестно",
        }.get(self.kind, self.kind)

    @property
    def media_display(self) -> str:
        return {
            "Registry": "Реестр",
            "HDD": "HDD",
            "USB": "USB/съёмный",
            "Network": "Сеть",
            "Unknown": "Неизвестно",
        }.get(self.media, self.media or "—")

    @property
    def location_display(self) -> str:
        if self.kind == "Registry":
            return self.reg_path or self.full_name or self.name
        if self.kind == "File":
            return self.path or self.full_name or self.name
        return self.full_name or self.name

    @property
    def status_display(self) -> str:
        return "ключ сохранён" if self.saved else "ключ НЕ сохранён"


@dataclass
class BackupContents:
    path: str
    created: str = ""
    password: str = ""
    certificates: List[RestoreCertificate] = field(default_factory=list)
    containers: List[RestoreContainer] = field(default_factory=list)
    legacy: bool = False
    warnings: List[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return os.path.basename(self.path.rstrip("\\/"))

    @property
    def created_display(self) -> str:
        value = _parse_iso(self.created)
        return format_dt(value) if value else (self.created or "—")


class BackupReader:
    """Прочитать резервную копию и вернуть её содержимое."""

    @classmethod
    def load(cls, path: str) -> BackupContents:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            raise RestoreError("Файл резервной копии не найден: %s" % path)
        if os.path.isdir(path):
            return cls._load_directory(path)
        if not zipfile.is_zipfile(path):
            raise RestoreError(
                "Файл не является резервной копией CryptoCleaner: %s" % path
            )
        try:
            with zipfile.ZipFile(path, "r") as archive:
                names = {
                    name
                    for name in archive.namelist()
                    if name and not name.endswith("/")
                }
                if "objects.json" in names:
                    data = json.loads(
                        archive.read("objects.json").decode("utf-8-sig")
                    )
                    password = cls._read_password_zip(archive, names)
                    return cls._from_objects(
                        path, data, names, password, legacy=False
                    )
                if "manifest.csv" in names:
                    text = archive.read("manifest.csv").decode(
                        "utf-8-sig", errors="replace"
                    )
                    password = cls._read_password_zip(archive, names)
                    return cls._from_manifest(
                        path, text, names, password, legacy=True
                    )
        except RestoreError:
            raise
        except Exception as exc:
            raise RestoreError("Не удалось прочитать архив: %s" % exc)
        raise RestoreError(
            "В архиве нет ни objects.json, ни manifest.csv. "
            "Это не резервная копия CryptoCleaner."
        )

    # ------------------------------------------------------------------
    # Новый формат
    # ------------------------------------------------------------------
    @classmethod
    def _from_objects(
        cls,
        path: str,
        data: Dict,
        names: set,
        password: str,
        legacy: bool,
    ) -> BackupContents:
        contents = BackupContents(
            path=path,
            created=str(data.get("created") or ""),
            password=str(data.get("password") or password or ""),
            legacy=legacy,
        )
        for item in data.get("certificates") or []:
            if not isinstance(item, dict):
                continue
            thumb = normalize_thumb(str(item.get("thumbprint") or ""))
            if not thumb:
                continue
            cer = cls._safe_member(str(item.get("cer") or ""), names)
            pfx = cls._safe_member(str(item.get("pfx") or ""), names)
            files = [
                cls._safe_member(str(name), names)
                for name in (item.get("files") or [])
            ]
            files = [name for name in files if name]
            if not cer and not pfx:
                contents.warnings.append(
                    "В архиве нет файлов сертификата %s" % thumb
                )
            locations = []
            for location in item.get("locations") or []:
                if not isinstance(location, dict):
                    continue
                entry = {
                    "store_name": str(location.get("store_name") or "My"),
                    "location": str(location.get("location") or "CurrentUser"),
                    "display": str(location.get("display") or ""),
                    "code": str(location.get("code") or ""),
                }
                if not entry["display"]:
                    entry["display"] = (
                        "%s (%s)"
                        % (
                            entry["store_name"],
                            "Пользователь"
                            if entry["location"] == "CurrentUser"
                            else "Компьютер",
                        )
                    )
                if not entry["code"]:
                    entry["code"] = (
                        ("u" if entry["location"] == "CurrentUser" else "m")
                        + {
                            "My": "My",
                            "CA": "CA",
                            "Root": "ROOT",
                        }.get(entry["store_name"], entry["store_name"])
                    )
                locations.append(entry)
            contents.certificates.append(
                RestoreCertificate(
                    thumbprint=thumb,
                    name=str(item.get("name") or thumb),
                    subject=str(item.get("subject") or ""),
                    issuer=str(item.get("issuer") or ""),
                    not_after=_parse_iso(str(item.get("not_after") or "")),
                    has_private_key=bool(item.get("has_private_key")),
                    saved=bool(item.get("saved", True)),
                    files=files,
                    cer=cer,
                    pfx=pfx,
                    pfx_has_key=(
                        bool(item.get("pfx_has_key"))
                        if item.get("pfx_has_key") is not None
                        else None
                    ),
                    locations=locations or [dict(DEFAULT_LOCATION)],
                    containers=[
                        str(value) for value in (item.get("containers") or [])
                    ],
                    note=str(item.get("note") or ""),
                )
            )

        for item in data.get("containers") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            key = str(item.get("key") or ("RESTORE:" + name))
            reg_path = str(item.get("reg_path") or "")
            hive = str(item.get("reg_hive") or "")
            subkey = str(item.get("reg_subkey") or "")
            wow = int(item.get("reg_wow64") or 0)
            if reg_path and (not hive or not subkey):
                hive, subkey, parsed_wow = _parse_reg_path(reg_path)
                wow = wow or parsed_wow
            files = [
                cls._safe_member(str(entry), names)
                for entry in (item.get("files") or [])
            ]
            files = [entry for entry in files if entry]
            contents.containers.append(
                RestoreContainer(
                    key=key,
                    name=name or os.path.basename(reg_path) or "контейнер",
                    kind=str(item.get("kind") or "Unknown"),
                    media=str(item.get("media") or ""),
                    path=str(item.get("path") or ""),
                    reg_path=reg_path,
                    reg_hive=hive,
                    reg_subkey=subkey,
                    reg_wow64=wow,
                    full_name=str(item.get("full_name") or ""),
                    internal_name=str(item.get("internal_name") or ""),
                    thumbprint=normalize_thumb(str(item.get("thumbprint") or "")),
                    subject=str(item.get("subject") or ""),
                    not_after=_parse_iso(str(item.get("not_after") or "")),
                    saved=bool(item.get("saved", True)),
                    files=files,
                    dir_entry=cls._safe_dir_member(
                        str(item.get("dir") or ""), names
                    ),
                    pfx_entry=cls._safe_member(str(item.get("pfx") or ""), names),
                    reg_entry=cls._safe_member(str(item.get("reg") or ""), names),
                    note=str(item.get("note") or ""),
                )
            )
        if not contents.certificates and not contents.containers:
            raise RestoreError("В резервной копии нет сертификатов и контейнеров.")
        return contents

    # ------------------------------------------------------------------
    # Старый формат (каталог или ZIP с manifest.csv)
    # ------------------------------------------------------------------
    @classmethod
    def _from_manifest(
        cls,
        path: str,
        text: str,
        names: set,
        password: str,
        legacy: bool,
    ) -> BackupContents:
        contents = BackupContents(
            path=path,
            created=datetime.fromtimestamp(
                os.path.getmtime(path)
            ).isoformat(timespec="seconds"),
            password=password,
            legacy=legacy,
        )
        rows = list(
            csv.DictReader(io.StringIO(text), delimiter=";")
        )
        for row in rows:
            kind = (row.get("Тип") or "").strip()
            if kind == "Сертификат":
                thumb = normalize_thumb(row.get("Отпечаток") or "")
                if not thumb:
                    continue
                cer = cls._find_cert_file(names, thumb, ".cer")
                pfx = cls._find_cert_file(names, thumb, ".pfx")
                files = [name for name in (cer, pfx) if name]
                if not files:
                    continue
                contents.certificates.append(
                    RestoreCertificate(
                        thumbprint=thumb,
                        name=(row.get("Имя") or thumb).strip(),
                        subject=(row.get("Субъект") or "").strip(),
                        issuer=(row.get("Издатель") or "").strip(),
                        not_after=_parse_iso(row.get("Действителен до") or ""),
                        has_private_key=bool(pfx),
                        saved="ошиб" not in (row.get("Статус") or "").lower(),
                        files=files,
                        cer=cer,
                        pfx=pfx,
                        pfx_has_key=None,
                        locations=_parse_locations(row.get("Расположение") or ""),
                        note=(row.get("Примечание") or "").strip(),
                    )
                )
            elif kind == "Контейнер":
                name = (row.get("Имя") or "").strip()
                if not name:
                    continue
                kind_value = (row.get("Тип контейнера") or "").strip()
                container_kind = (
                    "Registry"
                    if kind_value == "Реестр"
                    else "File"
                    if kind_value == "Файл"
                    else "Unknown"
                )
                location = (row.get("Путь") or "").strip()
                reg_path = location if container_kind == "Registry" else ""
                hive, subkey, wow = _parse_reg_path(reg_path)
                safe_name = safe_filename(name, 60)
                dir_entry = cls._find_container_dir(names, safe_name)
                pfx_entry = cls._find_named(names, "containers", safe_name, ".pfx")
                reg_entry = cls._find_named(names, "registry", safe_name, ".reg")
                files = [entry for entry in (dir_entry, pfx_entry, reg_entry) if entry]
                if not files:
                    continue
                contents.containers.append(
                    RestoreContainer(
                        key="LEGACY:" + name,
                        name=name,
                        kind=container_kind,
                        media=(row.get("Носитель") or "").strip(),
                        path=location if container_kind == "File" else "",
                        reg_path=reg_path,
                        reg_hive=hive,
                        reg_subkey=subkey,
                        reg_wow64=wow,
                        thumbprint=normalize_thumb(row.get("Отпечаток") or ""),
                        subject=(row.get("Субъект") or "").strip(),
                        not_after=_parse_iso(row.get("Действителен до") or ""),
                        saved="не сохран" not in (row.get("Статус") or "").lower(),
                        files=files,
                        dir_entry=dir_entry,
                        pfx_entry=pfx_entry,
                        reg_entry=reg_entry,
                        note=(row.get("Примечание") or "").strip(),
                    )
                )

        # Если manifest.csv пуст или неполон, добавляем сертификаты,
        # найденные в архиве по имени файла.
        known = {cert.thumbprint for cert in contents.certificates}
        for name in sorted(names):
            match = re.match(
                r"(?i)^certificates/([0-9A-F]{40})\.(cer|pfx)$", name
            )
            if not match:
                continue
            thumb = match.group(1).upper()
            if thumb in known:
                continue
            known.add(thumb)
            cer = cls._find_cert_file(names, thumb, ".cer")
            pfx = cls._find_cert_file(names, thumb, ".pfx")
            contents.certificates.append(
                RestoreCertificate(
                    thumbprint=thumb,
                    name=thumb,
                    files=[value for value in (cer, pfx) if value],
                    cer=cer,
                    pfx=pfx,
                    pfx_has_key=None,
                    has_private_key=bool(pfx),
                    locations=[dict(DEFAULT_LOCATION)],
                )
            )

        if not contents.certificates and not contents.containers:
            raise RestoreError(
                "В резервной копии не найдено сертификатов или контейнеров."
            )
        return contents

    @classmethod
    def _load_directory(cls, path: str) -> BackupContents:
        names: set = set()
        for current, _dirs, files in os.walk(path):
            for name in files:
                full = os.path.join(current, name)
                names.add(os.path.relpath(full, path).replace("\\", "/"))
        password = cls._read_password_dir(path, names)
        objects_path = os.path.join(path, "objects.json")
        if os.path.isfile(objects_path):
            try:
                with open(objects_path, "r", encoding="utf-8-sig") as fh:
                    data = json.load(fh)
                return cls._from_objects(path, data, names, password, legacy=False)
            except RestoreError:
                raise
            except Exception as exc:
                raise RestoreError("Не удалось прочитать objects.json: %s" % exc)
        manifest_path = os.path.join(path, "manifest.csv")
        if os.path.isfile(manifest_path):
            with open(manifest_path, "r", encoding="utf-8-sig", errors="replace") as fh:
                text = fh.read()
            return cls._from_manifest(path, text, names, password, legacy=True)
        raise RestoreError(
            "В каталоге нет ни objects.json, ни manifest.csv. "
            "Это не резервная копия CryptoCleaner."
        )

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_member(name: str, names: set) -> str:
        name = (name or "").replace("\\", "/").lstrip("/")
        if not name or name not in names:
            return ""
        parts = name.split("/")
        if any(part in ("..", "") for part in parts):
            return ""
        return name

    @staticmethod
    def _safe_dir_member(name: str, names: set) -> str:
        name = (name or "").replace("\\", "/").strip("/")
        if not name:
            return ""
        parts = name.split("/")
        if any(part in ("..", "") for part in parts):
            return ""
        prefix = name + "/"
        return name if any(entry.startswith(prefix) for entry in names) else ""

    @staticmethod
    def _find_cert_file(names: set, thumb: str, extension: str) -> str:
        target = ("certificates/%s%s" % (thumb, extension)).lower()
        for name in names:
            if name.lower() == target:
                return name
        return ""

    @staticmethod
    def _find_named(names: set, folder: str, base: str, extension: str) -> str:
        prefix = (folder + "/" + base).lower()
        for name in sorted(names):
            lowered = name.lower()
            if not lowered.startswith(prefix):
                continue
            rest = lowered[len(prefix):]
            if rest == extension or re.match(
                r"_\d+%s$" % re.escape(extension), rest
            ):
                return name
        return ""

    @staticmethod
    def _find_container_dir(names: set, base: str) -> str:
        prefix = ("containers/" + base).lower()
        candidates = set()
        for name in names:
            lowered = name.lower()
            if not lowered.startswith(prefix):
                continue
            parts = lowered.split("/")
            if len(parts) >= 3 and re.match(
                r"^%s(_\d+)?$" % re.escape(base.lower()), parts[1]
            ):
                candidates.add("containers/" + name.split("/")[1])
        return sorted(candidates)[0] if candidates else ""

    @staticmethod
    def _read_password_zip(archive: zipfile.ZipFile, names: set) -> str:
        if "PASSWORD.txt" not in names:
            return ""
        try:
            text = archive.read("PASSWORD.txt").decode("utf-8-sig", errors="replace")
        except Exception:
            return ""
        return BackupReader._parse_password(text)

    @staticmethod
    def _read_password_dir(path: str, names: set) -> str:
        if "PASSWORD.txt" not in names:
            return ""
        try:
            with open(
                os.path.join(path, "PASSWORD.txt"),
                "r",
                encoding="utf-8-sig",
                errors="replace",
            ) as fh:
                return BackupReader._parse_password(fh.read())
        except Exception:
            return ""

    @staticmethod
    def _parse_password(text: str) -> str:
        for line in (text or "").splitlines():
            value = line.strip()
            if not value:
                continue
            if "парол" in value.lower() or set(value) <= set("=- "):
                continue
            if " " in value:
                continue
            if len(value) >= 6:
                return value
        return ""


class _BackupSource:
    """Единый доступ к файлам ZIP-архива или каталога."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.is_zip = not os.path.isdir(path)

    def extract(self, member: str, destination: str) -> str:
        member = (member or "").replace("\\", "/").lstrip("/")
        parts = member.split("/")
        if not member or any(part in ("..", "") for part in parts):
            raise RestoreError("Недопустимый путь в архиве: %s" % member)
        target = os.path.join(destination, *parts)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if self.is_zip:
            with zipfile.ZipFile(self.path, "r") as archive:
                try:
                    info = archive.getinfo(member)
                except KeyError:
                    raise RestoreError("В архиве нет файла: %s" % member)
                with archive.open(info, "r") as source, open(target, "wb") as fh:
                    shutil.copyfileobj(source, fh)
        else:
            source = os.path.join(self.path, *parts)
            if not os.path.isfile(source):
                raise RestoreError("В резервной копии нет файла: %s" % member)
            shutil.copy2(source, target)
        return target

    def extract_dir(self, member: str, destination: str) -> str:
        """Извлечь каталог целиком и вернуть путь к нему."""
        member = (member or "").replace("\\", "/").rstrip("/")
        if not member:
            raise RestoreError("Не указан каталог контейнера.")
        if self.is_zip:
            prefix = member + "/"
            target = os.path.join(destination, *member.split("/"))
            os.makedirs(target, exist_ok=True)
            found = False
            with zipfile.ZipFile(self.path, "r") as archive:
                for info in archive.infolist():
                    name = info.filename.replace("\\", "/")
                    if not name.startswith(prefix) or name.endswith("/"):
                        continue
                    relative = name[len(prefix):]
                    parts = relative.split("/")
                    if any(part in ("..", "") for part in parts):
                        continue
                    output = os.path.join(target, *parts)
                    os.makedirs(os.path.dirname(output), exist_ok=True)
                    with archive.open(info, "r") as source, open(output, "wb") as fh:
                        shutil.copyfileobj(source, fh)
                    found = True
            if not found:
                raise RestoreError("Каталог контейнера пуст: %s" % member)
            return target
        source = os.path.join(self.path, *member.split("/"))
        if not os.path.isdir(source):
            raise RestoreError("В резервной копии нет каталога: %s" % member)
        target = os.path.join(destination, *member.split("/"))
        shutil.copytree(source, target)
        return target


class RestoreManager:
    def __init__(
        self,
        logger,
        tools: ToolRunner,
        cancel_event=None,
        progress=None,
    ) -> None:
        self.logger = logger
        self.tools = tools
        self.cancel_event = cancel_event
        self.progress = progress

    def _check_cancel(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise RestoreCancelled()

    def _report(self, text: str, current: int = 0, total: int = 0) -> None:
        if self.progress:
            try:
                self.progress(text, current, total)
            except Exception:
                pass

    def restore(
        self,
        contents: BackupContents,
        cert_thumbprints: List[str],
        container_keys: List[str],
        overwrite: bool = False,
    ) -> List[OperationResult]:
        selected_certs = [
            cert
            for cert in contents.certificates
            if cert.thumbprint in set(cert_thumbprints)
        ]
        selected_conts = [
            container
            for container in contents.containers
            if container.key in set(container_keys)
        ]
        if not selected_certs and not selected_conts:
            return []
        results: List[OperationResult] = []
        total = len(selected_certs) + len(selected_conts)
        current = 0
        source = _BackupSource(contents.path)
        temp = tempfile.mkdtemp(prefix="cryptocleaner_restore_")
        self.logger.info(
            "Восстановление из %s: сертификатов %d, контейнеров %d"
            % (contents.path, len(selected_certs), len(selected_conts))
        )
        try:
            for cert in selected_certs:
                self._check_cancel()
                current += 1
                self._report(
                    "Восстановление сертификата %s" % cert.name, current, total
                )
                try:
                    result = self._restore_certificate(
                        cert, contents.password, source, temp
                    )
                except RestoreCancelled:
                    raise
                except Exception as exc:
                    result = OperationResult(
                        kind="Сертификат",
                        name=cert.name,
                        success=False,
                        message="Ошибка восстановления: %s" % exc,
                        target_key="CERT:" + cert.thumbprint,
                    )
                results.append(result)
                self._log_result(result)

            for container in selected_conts:
                self._check_cancel()
                current += 1
                self._report(
                    "Восстановление контейнера %s" % container.name,
                    current,
                    total,
                )
                try:
                    result = self._restore_container(
                        container, contents.password, source, temp, overwrite
                    )
                except RestoreCancelled:
                    raise
                except Exception as exc:
                    result = OperationResult(
                        kind="Контейнер",
                        name=container.name,
                        success=False,
                        message="Ошибка восстановления: %s" % exc,
                        target_key=container.key,
                    )
                results.append(result)
                self._log_result(result)
        finally:
            shutil.rmtree(temp, ignore_errors=True)
        return results

    def _log_result(self, result: OperationResult) -> None:
        text = "%s: %s — %s" % (result.kind, result.name, result.message)
        if result.success:
            self.logger.ok(text)
        else:
            self.logger.error(text)

    # ------------------------------------------------------------------
    # Сертификаты
    # ------------------------------------------------------------------
    def _restore_certificate(
        self,
        cert: RestoreCertificate,
        password: str,
        source: _BackupSource,
        temp: str,
    ) -> OperationResult:
        details: List[str] = []
        methods: List[str] = []
        target_key = "CERT:" + cert.thumbprint
        cer_path = ""
        pfx_path = ""
        try:
            if cert.cer:
                cer_path = source.extract(cert.cer, temp)
            if cert.pfx:
                pfx_path = source.extract(cert.pfx, temp)
        except Exception as exc:
            return OperationResult(
                kind="Сертификат",
                name=cert.name,
                success=False,
                message="Не удалось извлечь файлы из копии: %s" % exc,
                details=details,
                methods=methods,
                target_key=target_key,
            )

        pfx_has_key = cert.pfx_has_key
        if pfx_has_key is None and pfx_path:
            pfx_has_key = pfx_has_private_key(pfx_path)
        pfx_has_key = bool(pfx_has_key)

        if not cer_path and not pfx_path:
            return OperationResult(
                kind="Сертификат",
                name=cert.name,
                success=False,
                message="В резервной копии нет файлов сертификата.",
                details=details,
                methods=methods,
                target_key=target_key,
            )

        locations = cert.locations or [dict(DEFAULT_LOCATION)]
        for location in locations:
            self._check_cancel()
            store_name = location.get("store_name") or "My"
            place = location.get("location") or "CurrentUser"
            code = location.get("code") or (
                ("u" if place == "CurrentUser" else "m")
                + {"My": "My", "CA": "CA", "Root": "ROOT"}.get(
                    store_name, store_name
                )
            )
            installed = False
            if (
                store_name == "My"
                and pfx_has_key
                and pfx_path
                and self.tools.certmgr
            ):
                if not password:
                    details.append(
                        "Пароль PFX не найден — установка ключа пропущена."
                    )
                else:
                    result = self.tools.run(
                        [
                            self.tools.certmgr,
                            "-install",
                            "-pfx",
                            "-file",
                            pfx_path,
                            "-pin",
                            password,
                            "-store",
                            code,
                            "-silent",
                        ],
                        timeout=90,
                        sensitive=True,
                        log_output=True,
                    )
                    methods.append("certmgr -install -pfx -store %s" % code)
                    if result.ok:
                        installed = True
                        details.append(
                            "PFX установлен в %s (%s)." % (store_name, place)
                        )
                    else:
                        details.append(
                            "certmgr -install -pfx (%s): %s"
                            % (code, (result.output or result.error or "").strip())
                        )
            if not installed and cer_path:
                args = [self.tools.certutil, "-addstore", "-f"]
                if place == "CurrentUser":
                    args.append("-user")
                args += [store_name, cer_path]
                result = self.tools.run(args, timeout=45, log_output=True)
                methods.append("certutil -addstore %s (%s)" % (store_name, place))
                if result.ok:
                    installed = True
                    details.append(
                        "Сертификат добавлен в %s (%s)." % (store_name, place)
                    )
                else:
                    details.append(
                        "certutil -addstore (%s): %s"
                        % (
                            store_name,
                            (result.output or result.error or "").strip(),
                        )
                    )
            if not installed and pfx_path and store_name == "My":
                # Последняя попытка: certmgr может установить сертификат
                # из PFX даже без доступного ключа.
                result = self.tools.run(
                    [
                        self.tools.certmgr,
                        "-install",
                        "-pfx",
                        "-file",
                        pfx_path,
                        "-pin",
                        password or "",
                        "-store",
                        code,
                        "-silent",
                    ],
                    timeout=90,
                    sensitive=True,
                    log_output=True,
                )
                methods.append("certmgr -install -pfx -store %s" % code)
                if result.ok:
                    installed = True
                    details.append(
                        "Сертификат из PFX установлен в %s (%s)."
                        % (store_name, place)
                    )

        # ------------------------------------------------------------------
        # Проверка результата
        # ------------------------------------------------------------------
        present_locations: List[str] = []
        present_keys = set()
        key_found = False
        for location in locations:
            store_name = location.get("store_name") or "My"
            place = location.get("location") or "CurrentUser"
            try:
                items = winapi.enum_certificates(store_name, place)
            except Exception as exc:
                details.append(
                    "Не удалось прочитать %s (%s): %s" % (store_name, place, exc)
                )
                continue
            for item in items:
                if item.get("thumbprint") != cert.thumbprint:
                    continue
                present_locations.append("%s (%s)" % (store_name, place))
                present_keys.add((store_name, place))
                if item.get("has_private_key"):
                    key_found = True
                break

        missing_locations = []
        for location in locations:
            key = (
                location.get("store_name") or "My",
                location.get("location") or "CurrentUser",
            )
            if key not in present_keys:
                missing_locations.append("%s (%s)" % key)

        if not present_locations:
            return OperationResult(
                kind="Сертификат",
                name=cert.name,
                success=False,
                message="Сертификат не найден в хранилищах после восстановления.",
                details=details,
                methods=methods,
                target_key=target_key,
            )
        if missing_locations:
            return OperationResult(
                kind="Сертификат",
                name=cert.name,
                success=False,
                message=(
                    "Сертификат восстановлен не во все хранилища. "
                    "Не найден в: %s. Восстановлен в: %s."
                    % (
                        ", ".join(missing_locations),
                        ", ".join(present_locations),
                    )
                ),
                details=details,
                methods=methods,
                target_key=target_key,
            )
        if pfx_has_key and not key_found:
            return OperationResult(
                kind="Сертификат",
                name=cert.name,
                success=False,
                message=(
                    "Сертификат установлен (%s), но закрытый ключ не найден. "
                    "Проверьте права и контейнер КриптоПро."
                    % ", ".join(present_locations)
                ),
                details=details,
                methods=methods,
                target_key=target_key,
            )
        message = "Сертификат восстановлен: %s." % ", ".join(present_locations)
        if pfx_has_key and key_found:
            message += " Закрытый ключ доступен."
        elif cert.has_private_key and not pfx_has_key:
            message += (
                " Закрытый ключ не входит в PFX (неэкспортируемый): "
                "для полного восстановления установите контейнер."
            )
            details.append(
                "PFX содержит только сертификат. Закрытый ключ восстанавливается "
                "из каталога контейнера или ветки реестра."
            )
        return OperationResult(
            kind="Сертификат",
            name=cert.name,
            success=True,
            message=message,
            details=details,
            methods=methods,
            target_key=target_key,
        )

    # ------------------------------------------------------------------
    # Контейнеры
    # ------------------------------------------------------------------
    def _restore_container(
        self,
        container: RestoreContainer,
        password: str,
        source: _BackupSource,
        temp: str,
        overwrite: bool,
    ) -> OperationResult:
        details: List[str] = []
        methods: List[str] = []
        if container.kind == "File" or container.dir_entry:
            return self._restore_file_container(
                container, source, temp, overwrite, details, methods
            )
        if container.kind == "Registry" or container.reg_entry:
            return self._restore_registry_container(
                container, source, temp, overwrite, details, methods
            )
        if container.pfx_entry:
            return self._restore_container_pfx(
                container, password, source, temp, details, methods
            )
        return OperationResult(
            kind="Контейнер",
            name=container.name,
            success=False,
            message="В резервной копии нет данных контейнера.",
            details=details,
            methods=methods,
            target_key=container.key,
        )

    def _restore_file_container(
        self,
        container: RestoreContainer,
        source: _BackupSource,
        temp: str,
        overwrite: bool,
        details: List[str],
        methods: List[str],
    ) -> OperationResult:
        if not container.path:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="Не указан исходный путь контейнера.",
                details=details,
                methods=methods,
                target_key=container.key,
            )
        if not container.dir_entry:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="В копии нет каталога файлового контейнера.",
                details=details,
                methods=methods,
                target_key=container.key,
            )
        target = container.path
        if os.path.exists(target):
            has_header = os.path.isfile(os.path.join(target, "header.key"))
            if not overwrite:
                return OperationResult(
                    kind="Контейнер",
                    name=container.name,
                    success=has_header,
                    message=(
                        "Контейнер уже существует%s — восстановление не требуется."
                        % (" и содержит header.key" if has_header else "")
                    ),
                    details=details,
                    methods=methods,
                    target_key=container.key,
                )
            backup = target.rstrip("\\/") + ".bak_" + datetime.now().strftime(
                "%Y%m%d_%H%M%S"
            )
            try:
                os.rename(target, backup)
                details.append("Старый контейнер сохранён: %s" % backup)
            except Exception as exc:
                return OperationResult(
                    kind="Контейнер",
                    name=container.name,
                    success=False,
                    message="Не удалось сохранить старый контейнер: %s" % exc,
                    details=details,
                    methods=methods,
                    target_key=container.key,
                )

        try:
            extracted = source.extract_dir(container.dir_entry, temp)
            os.makedirs(os.path.dirname(target.rstrip("\\/")), exist_ok=True)
            shutil.copytree(extracted, target)
            methods.append("копирование каталога контейнера")
            details.append("Каталог скопирован в %s" % target)
        except Exception as exc:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="Не удалось скопировать контейнер: %s" % exc,
                details=details,
                methods=methods,
                target_key=container.key,
            )

        header = os.path.join(target, "header.key")
        if os.path.isfile(header):
            details.append("header.key найден в восстановленном контейнере.")
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=True,
                message="Контейнер восстановлен: %s" % target,
                details=details,
                methods=methods,
                target_key=container.key,
            )
        return OperationResult(
            kind="Контейнер",
            name=container.name,
            success=False,
            message=(
                "Каталог скопирован, но header.key не найден. "
                "Контейнер может быть неработоспособен."
            ),
            details=details,
            methods=methods,
            target_key=container.key,
        )

    def _reg_key_state(self, container: RestoreContainer) -> str:
        hive = HIVES.get((container.reg_hive or "").upper())
        subkey = container.reg_subkey or ""
        if hive is None or not subkey:
            return "unknown"
        wow = container.reg_wow64 or 0
        if (container.reg_hive or "").upper() == "HKU":
            sid = subkey.split("\\", 1)[0]
            try:
                with winreg.OpenKey(hive, sid, 0, winreg.KEY_READ | wow):
                    pass
            except OSError:
                return "unknown"
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | wow):
                return "present"
        except FileNotFoundError:
            return "absent"
        except OSError:
            return "unknown"

    def _restore_registry_container(
        self,
        container: RestoreContainer,
        source: _BackupSource,
        temp: str,
        overwrite: bool,
        details: List[str],
        methods: List[str],
    ) -> OperationResult:
        if not container.reg_entry:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="В копии нет файла реестра контейнера.",
                details=details,
                methods=methods,
                target_key=container.key,
            )
        state = self._reg_key_state(container)
        if state == "present" and not overwrite:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=True,
                message="Ветка реестра уже существует — восстановление не требуется.",
                details=details,
                methods=methods,
                target_key=container.key,
            )
        try:
            reg_file = source.extract(container.reg_entry, temp)
        except Exception as exc:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="Не удалось извлечь .reg: %s" % exc,
                details=details,
                methods=methods,
                target_key=container.key,
            )
        args = [self.tools.reg, "import", reg_file]
        if container.reg_wow64 == KEY_WOW64_32KEY:
            args.append("/reg:32")
        elif container.reg_wow64 == KEY_WOW64_64KEY:
            args.append("/reg:64")
        result = self.tools.run(args, timeout=90, log_output=True)
        methods.append("reg import")
        if not result.ok:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="Импорт реестра не удался: %s"
                % (result.output or result.error or "").strip(),
                details=details,
                methods=methods,
                target_key=container.key,
            )
        state = self._reg_key_state(container)
        if state == "present":
            details.append("Ветка реестра найдена после импорта.")
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=True,
                message="Контейнер реестра восстановлен: %s"
                % (container.reg_path or container.name),
                details=details,
                methods=methods,
                target_key=container.key,
            )
        if state == "absent":
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message=(
                    "Импорт выполнен, но ветка реестра не найдена. "
                    "Проверьте разрядность и права."
                ),
                details=details,
                methods=methods,
                target_key=container.key,
            )
        details.append(
            "Импорт выполнен, но проверить ветку реестра не удалось "
            "(нет доступа или улей HKU не загружен)."
        )
        return OperationResult(
            kind="Контейнер",
            name=container.name,
            success=False,
            message=(
                "Импорт реестра выполнен, но результат не удалось проверить. "
                "Запустите программу от имени администратора."
            ),
            details=details,
            methods=methods,
            target_key=container.key,
        )

    def _restore_container_pfx(
        self,
        container: RestoreContainer,
        password: str,
        source: _BackupSource,
        temp: str,
        details: List[str],
        methods: List[str],
    ) -> OperationResult:
        if not self.tools.certmgr:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="certmgr.exe не найден — установить PFX невозможно.",
                details=details,
                methods=methods,
                target_key=container.key,
            )
        try:
            pfx_path = source.extract(container.pfx_entry, temp)
        except Exception as exc:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="Не удалось извлечь PFX: %s" % exc,
                details=details,
                methods=methods,
                target_key=container.key,
            )
        if not pfx_has_private_key(pfx_path):
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message=(
                    "PFX не содержит закрытого ключа (ключ неэкспортируемый). "
                    "Восстановите каталог контейнера или ветку реестра."
                ),
                details=details,
                methods=methods,
                target_key=container.key,
            )
        if not password:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="Не найден пароль PFX (PASSWORD.txt).",
                details=details,
                methods=methods,
                target_key=container.key,
            )
        result = self.tools.run(
            [
                self.tools.certmgr,
                "-install",
                "-pfx",
                "-file",
                pfx_path,
                "-pin",
                password,
                "-store",
                "uMy",
                "-silent",
            ],
            timeout=90,
            sensitive=True,
            log_output=True,
        )
        methods.append("certmgr -install -pfx -store uMy")
        if not result.ok:
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=False,
                message="Установка PFX не удалась: %s"
                % (result.output or result.error or "").strip(),
                details=details,
                methods=methods,
                target_key=container.key,
            )
        if container.thumbprint and winapi.cert_present(
            "My", "CurrentUser", container.thumbprint
        ):
            details.append(
                "PFX установлен в личное хранилище пользователя; "
                "исходный путь контейнера не восстанавливается."
            )
            return OperationResult(
                kind="Контейнер",
                name=container.name,
                success=True,
                message=(
                    "Контейнер восстановлен из PFX в хранилище пользователя. "
                    "Исходное расположение контейнера не сохраняется."
                ),
                details=details,
                methods=methods,
                target_key=container.key,
            )
        return OperationResult(
            kind="Контейнер",
            name=container.name,
            success=False,
            message="PFX установлен, но сертификат с ключом не найден.",
            details=details,
            methods=methods,
            target_key=container.key,
        )
