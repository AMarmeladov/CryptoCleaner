"""Резервное копирование сертификатов и контейнеров CryptoCleaner.

Резервная копия создаётся в один файл ``*.ccbackup`` — это обычный ZIP-архив
со следующей структурой::

    certificates/   — сертификаты (.cer), закрытые ключи (.pfx), описания (.txt)
    containers/     — копии файловых контейнеров, PFX и описания
    registry/       — экспорт веток реестра (.reg) и настроек КриптоПро
    manifest.csv    — таблица объектов для просмотра в Excel
    objects.json    — служебные данные для точного восстановления
    PASSWORD.txt    — пароль к PFX-файлам
    README.txt      — инструкция по восстановлению
    log_copy.log    — копия журнала работы (если доступна)

Архив не шифруется средствами ZIP: он содержит закрытые ключи, поэтому
хранить его нужно в защищённом месте.
"""
from __future__ import annotations

import csv
import json
import os
import secrets
import shutil
import tempfile
import zipfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from . import winapi
from .model import (
    BackupSummary,
    Certificate,
    Container,
    format_dt,
    safe_filename,
)
from .tools import KEY_WOW64_32KEY, KEY_WOW64_64KEY, ToolRunner

BACKUP_EXTENSION = ".ccbackup"
BACKUP_FORMAT = "CryptoCleaner backup"
BACKUP_FORMAT_VERSION = 2


def _test_writable(directory: str) -> bool:
    try:
        os.makedirs(directory, exist_ok=True)
        probe = os.path.join(directory, ".cc_backup_%s.tmp" % os.getpid())
        with open(probe, "w", encoding="ascii") as fh:
            fh.write("ok")
        os.remove(probe)
        return True
    except Exception:
        return False


def choose_backup_root(base_dir: str) -> str:
    documents = ""
    try:
        documents = os.path.join(
            os.path.expanduser("~"), "Documents", "CryptoCleaner_Backups"
        )
    except Exception:
        documents = ""
    candidates = [
        os.path.join(base_dir, "Backups") if base_dir else "",
        documents,
        os.path.join(tempfile.gettempdir(), "CryptoCleaner_Backups"),
    ]
    for candidate in candidates:
        if candidate and _test_writable(candidate):
            return candidate
    return tempfile.gettempdir()


def generate_password(length: int = 18) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class BackupCancelled(Exception):
    pass


PKCS12_KEY_BAG_OID = bytes.fromhex("060B2A864886F70D010C0A0102")


def pfx_has_private_key(path: str) -> Optional[bool]:
    """Есть ли в PFX контейнер закрытого ключа (pkcs8ShroudedKeyBag)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        return PKCS12_KEY_BAG_OID in data
    except Exception:
        return None


def collect_backup_containers(
    certificates: List[Certificate],
    containers: List[Container],
) -> List[Container]:
    """Добавить к копии контейнеры, связанные с выбранными сертификатами.

    Если у сертификата есть закрытый ключ, а его контейнер не выбран для
    удаления, ключ всё равно нужно сохранить: иначе восстановление
    сертификата вместе с ключом не гарантировано.
    """
    result = list(containers)
    known = {container.key for container in result}
    for cert in certificates:
        if not cert.has_private_key:
            continue
        for container in cert.containers:
            if container.key in known:
                continue
            known.add(container.key)
            result.append(container)
    return result


def _archive_name(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace("\\", "/")


class BackupManager:
    def __init__(
        self,
        logger,
        tools: ToolRunner,
        base_dir: str = "",
        cancel_event=None,
        progress=None,
    ) -> None:
        self.logger = logger
        self.tools = tools
        self.base_dir = base_dir
        self.cancel_event = cancel_event
        self.progress = progress
        self.password = ""

    def _check_cancel(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise BackupCancelled()

    def _report(self, text: str, current: int = 0, total: int = 0) -> None:
        if self.progress:
            try:
                self.progress(text, current, total)
            except Exception:
                pass

    def _write_text(self, path: str, text: str) -> None:
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            fh.write(text)

    def _new_backup_path(self) -> str:
        root = choose_backup_root(self.base_dir)
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = os.path.join(root, "CryptoCleaner_Backup_" + stamp + BACKUP_EXTENSION)
        counter = 1
        while os.path.exists(path):
            path = os.path.join(
                root,
                "CryptoCleaner_Backup_%s_%d%s" % (stamp, counter, BACKUP_EXTENSION),
            )
            counter += 1
        return path

    # ------------------------------------------------------------------
    # Публичный метод
    # ------------------------------------------------------------------
    def create_backup(
        self,
        certificates: List[Certificate],
        containers: List[Container],
        password: str = "",
        include_settings: bool = True,
        log_path: str = "",
    ) -> BackupSummary:
        self._check_cancel()
        backup_path = self._new_backup_path()
        staging = tempfile.mkdtemp(prefix="cryptocleaner_backup_")
        cert_dir = os.path.join(staging, "certificates")
        cont_dir = os.path.join(staging, "containers")
        reg_dir = os.path.join(staging, "registry")
        for directory in (cert_dir, cont_dir, reg_dir):
            os.makedirs(directory, exist_ok=True)

        self.password = password or generate_password()
        summary = BackupSummary(path=backup_path, password=self.password)
        manifest: List[Dict[str, str]] = []
        objects: Dict[str, object] = {
            "format": BACKUP_FORMAT,
            "format_version": BACKUP_FORMAT_VERSION,
            "app": "CryptoCleaner",
            "created": datetime.now().isoformat(timespec="seconds"),
            "password": self.password,
            "certificates": [],
            "containers": [],
        }
        self.logger.info("Создание резервной копии: %s" % backup_path)
        self.logger.info(
            "Объектов в резервной копии: сертификатов %d, контейнеров %d"
            % (len(certificates), len(containers))
        )

        total = max(1, len(certificates) + len(containers))
        current = 0

        try:
            for cert in certificates:
                self._check_cancel()
                current += 1
                self._report(
                    "Резервная копия: сертификат %s" % cert.display_name,
                    current,
                    total,
                )
                files, cert_saved, info = self._backup_certificate(cert, cert_dir)
                if cert_saved:
                    summary.certs += 1
                else:
                    summary.failures += 1
                    message = (
                        "Не удалось сохранить сертификат %s (%s). "
                        "Удаление остановлено, чтобы не потерять данные."
                        % (cert.thumbprint, cert.display_name)
                    )
                    summary.messages.append(message)
                    self.logger.error(message)
                if cert.has_private_key:
                    pfx_file = info.get("pfx_path", "")
                    if pfx_file and pfx_has_private_key(pfx_file):
                        summary.keys_exported += 1
                    else:
                        summary.keys_missing += 1
                        message = (
                            "Закрытый ключ сертификата %s не экспортирован в PFX "
                            "(ключ неэкспортируемый). Для восстановления "
                            "используйте копию контейнера или экспорт реестра."
                            % cert.thumbprint
                        )
                        summary.messages.append(message)
                        self.logger.warn(message)
                rel_files = [_archive_name(p, staging) for p in files]
                manifest.append(
                    self._cert_manifest_row(cert, rel_files, cert_saved)
                )
                summary.files += len(files)
                objects["certificates"].append(  # type: ignore[index]
                    self._cert_object(cert, rel_files, cert_saved, info, staging)
                )

            for container in containers:
                self._check_cancel()
                current += 1
                self._report(
                    "Резервная копия: контейнер %s" % container.name,
                    current,
                    total,
                )
                files, key_saved, info = self._backup_container(
                    container, cont_dir, reg_dir
                )
                if key_saved:
                    summary.containers += 1
                else:
                    summary.failures += 1
                    message = (
                        "Не удалось сохранить ключевые данные контейнера: %s "
                        "(%s). Удаление остановлено, чтобы не потерять ключ."
                        % (container.name, container.location_display)
                    )
                    summary.messages.append(message)
                    self.logger.error(message)
                rel_files = [_archive_name(p, staging) for p in files]
                manifest.append(
                    self._container_manifest_row(container, rel_files, key_saved)
                )
                summary.files += len(files)
                objects["containers"].append(  # type: ignore[index]
                    self._container_object(
                        container, rel_files, key_saved, info, staging
                    )
                )

            if include_settings:
                self._backup_settings(reg_dir, summary)

            self._write_manifest(staging, manifest)
            self._write_password_file(staging, summary)
            if log_path and os.path.isfile(log_path):
                try:
                    target = os.path.join(staging, "log_copy.log")
                    shutil.copy2(log_path, target)
                    summary.log_copy = target
                    summary.files += 1
                except Exception as exc:
                    self.logger.warn(
                        "Не удалось скопировать журнал в резервную копию: %s" % exc
                    )

            self._write_readme(staging, summary, summary.certs, summary.containers)
            self._write_objects(staging, objects)

            self._check_cancel()
            self._report("Упаковка резервной копии в один файл...", total, total)
            self._make_archive(staging, backup_path)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

        try:
            with zipfile.ZipFile(backup_path, "r") as archive:
                summary.files = len([n for n in archive.namelist() if not n.endswith("/")])
        except Exception:
            summary.files = 0

        self._report("Проверка резервной копии...", total, total)
        self.verify_backup(summary, certificates, containers)
        if summary.verified:
            self.logger.ok(
                "Резервная копия создана и проверена: %s (файлов: %d)"
                % (backup_path, summary.files)
            )
        else:
            self.logger.error(
                "Резервная копия создана, но НЕ подтверждена: %s "
                "(файлов: %d, ошибок: %d)"
                % (backup_path, summary.files, summary.failures)
            )
        return summary

    def _make_archive(self, staging: str, backup_path: str) -> None:
        directory = os.path.dirname(os.path.abspath(backup_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        temporary = backup_path + ".part"
        try:
            with zipfile.ZipFile(
                temporary,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=6,
                allowZip64=True,
            ) as archive:
                for current, _dirs, files in os.walk(staging):
                    for name in sorted(files):
                        full = os.path.join(current, name)
                        arcname = _archive_name(full, staging)
                        archive.write(full, arcname)
            os.replace(temporary, backup_path)
        except Exception:
            try:
                if os.path.exists(temporary):
                    os.remove(temporary)
            except Exception:
                pass
            raise

    # ------------------------------------------------------------------
    # Проверка готовой резервной копии
    # ------------------------------------------------------------------
    def _file_ok(self, archive: zipfile.ZipFile, names: set, name: str) -> bool:
        """Есть ли файл в архиве и не пуст ли он."""
        name = (name or "").replace("\\", "/").lstrip("/")
        if not name or name not in names:
            return False
        try:
            return archive.getinfo(name).file_size > 0
        except KeyError:
            return False

    def _pfx_has_key(
        self, archive: zipfile.ZipFile, names: set, name: str
    ) -> bool:
        """Содержит ли PFX внутри архива контейнер закрытого ключа."""
        if not self._file_ok(archive, names, name):
            return False
        try:
            return PKCS12_KEY_BAG_OID in archive.read(name)
        except Exception:
            return False

    def _container_entry_ok(
        self,
        archive: zipfile.ZipFile,
        names: set,
        entry: Dict[str, object],
    ) -> bool:
        """Есть ли в архиве пригодные ключевые данные контейнера."""
        directory = str(entry.get("dir") or "").replace("\\", "/").strip("/")
        if directory:
            prefix = directory + "/"
            for member in names:
                if not member.startswith(prefix):
                    continue
                if member.split("/")[-1] != "header.key":
                    continue
                try:
                    if archive.getinfo(member).file_size > 0:
                        return True
                except KeyError:
                    continue
        if self._file_ok(archive, names, str(entry.get("reg") or "")):
            return True
        if self._pfx_has_key(archive, names, str(entry.get("pfx") or "")):
            return True
        return False

    def verify_backup(
        self,
        summary: BackupSummary,
        certificates: Optional[List[Certificate]] = None,
        containers: Optional[List[Container]] = None,
    ) -> BackupSummary:
        """Проверить итоговый файл копии и найти невосстановимые объекты.

        Проверяется именно готовый ``*.ccbackup``: целостность ZIP,
        обязательные файлы, objects.json и наличие реальных ключевых данных.
        Всё, что нельзя восстановить, попадает в ``summary.unrestorable`` —
        удаление таких объектов должно быть запрещено.
        """
        summary.verified = False
        summary.verification_messages = []
        summary.unrestorable = []
        messages = summary.verification_messages
        unrestorable = summary.unrestorable

        def fail(text: str) -> BackupSummary:
            messages.append(text)
            self.logger.error("Проверка резервной копии: %s" % text)
            return summary

        if not summary.path or not os.path.isfile(summary.path):
            return fail(
                "Файл резервной копии не найден: %s" % (summary.path or "—")
            )

        try:
            archive = zipfile.ZipFile(summary.path, "r")
        except Exception as exc:
            return fail("Не удалось открыть резервную копию: %s" % exc)

        try:
            try:
                damaged = archive.testzip()
            except Exception as exc:
                return fail("Не удалось проверить целостность архива: %s" % exc)
            if damaged:
                return fail("Повреждён файл внутри архива: %s" % damaged)

            names = set(archive.namelist())
            required = (
                "objects.json",
                "manifest.csv",
                "PASSWORD.txt",
                "README.txt",
            )
            missing = [name for name in required if name not in names]
            if missing:
                return fail(
                    "В резервной копии нет обязательных файлов: %s"
                    % ", ".join(missing)
                )

            try:
                data = json.loads(
                    archive.read("objects.json").decode("utf-8-sig")
                )
            except Exception as exc:
                return fail("Не удалось прочитать objects.json: %s" % exc)
            if not isinstance(data, dict):
                return fail("objects.json имеет неверный формат")

            cert_entries = [
                item
                for item in (data.get("certificates") or [])
                if isinstance(item, dict)
            ]
            cont_entries = [
                item
                for item in (data.get("containers") or [])
                if isinstance(item, dict)
            ]
            if not cert_entries and not cont_entries:
                return fail(
                    "В objects.json нет ни сертификатов, ни контейнеров"
                )

            # Контейнеры: ключевые данные должны реально читаться из архива.
            good_containers: Dict[str, Dict[str, object]] = {}
            for entry in cont_entries:
                name = str(
                    entry.get("name") or entry.get("key") or "контейнер"
                )
                if not bool(entry.get("saved", True)):
                    unrestorable.append(
                        "Контейнер «%s»: ключ не сохранён" % name
                    )
                    continue
                if not self._container_entry_ok(archive, names, entry):
                    unrestorable.append(
                        "Контейнер «%s»: в архиве нет пригодных ключевых "
                        "данных (header.key, .reg или PFX с ключом)" % name
                    )
                    continue
                good_containers[name] = entry
                thumb = str(entry.get("thumbprint") or "").upper()
                if thumb:
                    good_containers["THUMB:" + thumb] = entry

            # Сертификаты: публичный сертификат или ключ из PFX/контейнера.
            for entry in cert_entries:
                thumb = str(entry.get("thumbprint") or "").upper()
                name = str(entry.get("name") or thumb or "сертификат")
                has_key = bool(entry.get("has_private_key"))
                cer_ok = self._file_ok(
                    archive, names, str(entry.get("cer") or "")
                )
                pfx_key_ok = self._pfx_has_key(
                    archive, names, str(entry.get("pfx") or "")
                )

                if not bool(entry.get("saved", True)):
                    unrestorable.append(
                        "Сертификат «%s»: не сохранён" % name
                    )
                    continue
                if not has_key:
                    if not (cer_ok or pfx_key_ok):
                        unrestorable.append(
                            "Сертификат «%s»: нет читаемого файла .cer"
                            % name
                        )
                    continue
                if pfx_key_ok:
                    continue

                # Ключ неэкспортируемый: нужен сохранённый контейнер.
                container_ok = bool(
                    good_containers.get("THUMB:" + thumb)
                )
                if not container_ok:
                    for container_name in entry.get("containers") or []:
                        if good_containers.get(str(container_name)):
                            container_ok = True
                            break
                if not container_ok:
                    unrestorable.append(
                        "Сертификат «%s»: закрытого ключа нет в PFX и "
                        "не сохранён связанный контейнер" % name
                    )
        finally:
            try:
                archive.close()
            except Exception:
                pass

        if summary.failures:
            messages.append(
                "При создании копии зафиксировано ошибок: %d"
                % summary.failures
            )
        if unrestorable:
            messages.append(
                "Не гарантируется восстановление объектов: %d"
                % len(unrestorable)
            )
            for text in unrestorable:
                self.logger.warn("Не восстановить: %s" % text)

        summary.verified = not summary.failures and not unrestorable
        if summary.verified:
            self.logger.ok(
                "Резервная копия проверена: сертификатов %d, контейнеров %d, "
                "все объекты восстановимы"
                % (len(cert_entries), len(cont_entries))
            )
        else:
            self.logger.error(
                "Резервная копия НЕ подтверждена: восстановление всех "
                "объектов не гарантируется"
            )
        return summary

    # ------------------------------------------------------------------
    # Сертификаты
    # ------------------------------------------------------------------
    def _backup_certificate(
        self, cert: Certificate, cert_dir: str
    ) -> Tuple[List[str], bool, Dict[str, str]]:
        """Сохранить сертификат. Вернуть (файлы, сохранены ли данные, сведения).

        Успехом считается сохранённый .cer или PFX, реально содержащий
        закрытый ключ. Одно описание .txt успехом не считается.
        """
        files: List[str] = []
        cert_saved = False
        info: Dict[str, str] = {}
        base = safe_filename(cert.thumbprint, 60)
        raw = cert.raw or self._find_cert_raw(cert)
        if raw:
            cer_path = os.path.join(cert_dir, base + ".cer")
            try:
                with open(cer_path, "wb") as fh:
                    fh.write(raw)
                files.append(cer_path)
                info["cer_path"] = cer_path
                cert_saved = True
                self.logger.debug("Сохранён сертификат: %s" % cer_path)
            except Exception as exc:
                self.logger.warn("Не удалось сохранить .cer %s: %s" % (base, exc))
        else:
            self.logger.warn(
                "Нет DER-данных сертификата %s" % cert.thumbprint
            )

        if cert.has_private_key:
            pfx_path = os.path.join(cert_dir, base + ".pfx")
            if self._export_pfx(cert, pfx_path):
                files.append(pfx_path)
                info["pfx_path"] = pfx_path
                if pfx_has_private_key(pfx_path):
                    cert_saved = True
                    self.logger.ok("Экспортирован PFX с ключом: %s" % pfx_path)
                else:
                    self.logger.warn(
                        "Экспортирован PFX без закрытого ключа "
                        "(ключ неэкспортируемый): %s" % pfx_path
                    )
            else:
                self.logger.warn(
                    "Не удалось экспортировать PFX для %s" % cert.thumbprint
                )

        meta_path = os.path.join(cert_dir, base + ".txt")
        try:
            self._write_text(meta_path, self._cert_metadata(cert))
            files.append(meta_path)
            info["meta_path"] = meta_path
        except Exception as exc:
            self.logger.warn("Не удалось записать описание сертификата: %s" % exc)
        return files, cert_saved, info

    def _find_cert_raw(self, cert: Certificate) -> bytes:
        for location in cert.locations:
            try:
                items = winapi.enum_certificates(
                    location.store_name, location.location
                )
            except Exception:
                continue
            for item in items:
                if item.get("thumbprint") == cert.thumbprint:
                    return item.get("raw", b"")
        return b""

    def _export_pfx(self, cert: Certificate, target: str) -> bool:
        """Экспорт PFX. Основной путь — certmgr -export -store (КриптоПро),
        резервный — certutil -exportPFX с коротким таймаутом."""
        if self.tools.certmgr:
            for location in cert.locations:
                try:
                    if os.path.exists(target):
                        os.remove(target)
                except Exception:
                    pass
                args = [
                    self.tools.certmgr,
                    "-export",
                    "-store",
                    location.code,
                    "-thumbprint",
                    cert.thumbprint,
                    "-pfx",
                    "-dest",
                    target,
                    "-pin",
                    self.password,
                    "-silent",
                ]
                result = self.tools.run(
                    args, timeout=45, sensitive=True, log_output=True
                )
                if (
                    result.ok
                    and os.path.isfile(target)
                    and os.path.getsize(target) > 0
                ):
                    return True
                if result.timed_out:
                    self.logger.warn(
                        "certmgr -export: таймаут для %s (%s)"
                        % (cert.thumbprint, location.code)
                    )

        # Резервный путь: certutil. Может зависнуть на ключах КриптоПро,
        # поэтому таймаут намеренно короткий.
        if self.tools.certutil:
            for location in cert.locations:
                try:
                    if os.path.exists(target):
                        os.remove(target)
                except Exception:
                    pass
                args = [self.tools.certutil, "-exportPFX", "-p", self.password]
                if location.location == "CurrentUser":
                    args.append("-user")
                args += [location.store_name, cert.thumbprint, target]
                result = self.tools.run(
                    args, timeout=25, sensitive=True, log_output=True
                )
                if (
                    result.ok
                    and os.path.isfile(target)
                    and os.path.getsize(target) > 0
                ):
                    return True
                if result.timed_out:
                    self.logger.warn(
                        "certutil -exportPFX: таймаут для %s" % cert.thumbprint
                    )
                    break

        # Последний путь: экспорт через контейнер КриптоПро
        for container in cert.containers:
            if self._export_container_pfx(container, target):
                return True
        return False

    def _cert_metadata(self, cert: Certificate) -> str:
        lines = [
            "Сертификат",
            "==========",
            "Отпечаток (SHA1): %s" % cert.thumbprint,
            "Субъект: %s" % cert.subject,
            "Издатель: %s" % cert.issuer,
            "CN: %s" % cert.cn,
            "Действителен с: %s" % format_dt(cert.not_before),
            "Действителен до: %s" % format_dt(cert.not_after),
            "Закрытый ключ: %s" % ("да" if cert.has_private_key else "нет"),
            "Серийный номер: %s" % cert.serial,
            "Хранилища:",
        ]
        for location in cert.locations:
            lines.append("  - %s (%s)" % (location.display, location.code))
        if cert.containers:
            lines.append("Контейнеры:")
            for container in cert.containers:
                lines.append("  - %s" % container.name)
                if container.path:
                    lines.append("    путь: %s" % container.path)
                if container.reg_path:
                    lines.append("    реестр: %s" % container.reg_path)
        lines.append("")
        return "\r\n".join(lines)

    def _cert_manifest_row(
        self, cert: Certificate, files: List[str], cert_saved: bool
    ) -> Dict[str, str]:
        return {
            "Тип": "Сертификат",
            "Имя": cert.display_name,
            "Отпечаток": cert.thumbprint,
            "Субъект": cert.subject,
            "Издатель": cert.issuer,
            "Действителен до": format_dt(cert.not_after),
            "Расположение": cert.source_display,
            "Тип контейнера": "",
            "Носитель": "",
            "Путь": "",
            "Файлы резервной копии": "; ".join(files),
            "Статус": "сохранён" if cert_saved else "ошибка",
            "Примечание": cert.note,
        }

    def _cert_object(
        self,
        cert: Certificate,
        files: List[str],
        cert_saved: bool,
        info: Dict[str, str],
        staging: str,
    ) -> Dict[str, object]:
        cer = info.get("cer_path", "")
        pfx = info.get("pfx_path", "")
        return {
            "thumbprint": cert.thumbprint,
            "name": cert.display_name,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "cn": cert.cn,
            "not_after": cert.not_after.isoformat() if cert.not_after else "",
            "has_private_key": bool(cert.has_private_key),
            "saved": bool(cert_saved),
            "files": list(files),
            "cer": _archive_name(cer, staging) if cer else "",
            "pfx": _archive_name(pfx, staging) if pfx else "",
            "pfx_has_key": bool(pfx and pfx_has_private_key(pfx)),
            "locations": [
                {
                    "store_name": loc.store_name,
                    "location": loc.location,
                    "display": loc.display,
                    "code": loc.code,
                }
                for loc in cert.locations
            ],
            "containers": [c.name for c in cert.containers],
            "note": cert.note,
        }

    # ------------------------------------------------------------------
    # Контейнеры
    # ------------------------------------------------------------------
    def _backup_container(
        self, container: Container, cont_dir: str, reg_dir: str
    ) -> Tuple[List[str], bool, Dict[str, str]]:
        """Сохранить контейнер. Вернуть (файлы, сохранены ли ключевые данные, сведения).

        Ключевые данные — это копия каталога с header.key, экспорт ветки
        реестра или PFX, реально содержащий закрытый ключ. Описание .txt
        само по себе ключом не является и успехом не считается.
        """
        files: List[str] = []
        key_saved = False
        info: Dict[str, str] = {}
        safe_name = safe_filename(container.name or "container", 60)
        if container.kind == "File" and container.path:
            source = container.path
            target = os.path.join(cont_dir, safe_name)
            counter = 1
            while os.path.exists(target):
                target = os.path.join(cont_dir, "%s_%d" % (safe_name, counter))
                counter += 1
            try:
                shutil.copytree(source, target)
                files.extend(self._walk_files(target))
                key_saved = os.path.isfile(os.path.join(target, "header.key"))
                info["dir_path"] = target
                self.logger.debug("Скопирован контейнер: %s -> %s" % (source, target))
                if not key_saved:
                    self.logger.warn(
                        "В копии контейнера %s нет header.key" % target
                    )
            except Exception as exc:
                self.logger.warn(
                    "Не удалось скопировать контейнер %s: %s" % (source, exc)
                )
        elif container.kind == "Registry" and container.reg_path:
            reg_path = container.reg_path.replace(" [32-bit]", "")
            target = os.path.join(reg_dir, safe_name + ".reg")
            counter = 1
            while os.path.exists(target):
                target = os.path.join(reg_dir, "%s_%d.reg" % (safe_name, counter))
                counter += 1
            result = self.tools.reg_export(
                reg_path, target, container.reg_wow64, timeout=90
            )
            if result.ok and os.path.isfile(target) and os.path.getsize(target) > 0:
                files.append(target)
                info["reg_path"] = target
                key_saved = True
                self.logger.debug("Экспортирован ключ реестра: %s" % reg_path)
            else:
                self.logger.warn(
                    "Не удалось экспортировать ключ реестра %s: %s"
                    % (reg_path, result.output.strip() or result.error)
                )
        else:
            self.logger.warn(
                "Контейнер %s: неизвестно расположение, копирование невозможно"
                % container.name
            )

        # Дополнительно пробуем выгрузить PFX контейнера. Это запасной
        # вариант: у неэкспортируемых ключей PFX содержит только сертификат.
        pfx_target = os.path.join(cont_dir, safe_name + ".pfx")
        if self._export_container_pfx(container, pfx_target):
            files.append(pfx_target)
            info["pfx_path"] = pfx_target
            if pfx_has_private_key(pfx_target):
                key_saved = True
                self.logger.debug(
                    "Экспортирован PFX контейнера с ключом: %s" % pfx_target
                )
            else:
                self.logger.debug(
                    "PFX контейнера без закрытого ключа "
                    "(ключ неэкспортируемый): %s" % pfx_target
                )

        meta_path = os.path.join(cont_dir, safe_name + ".txt")
        try:
            self._write_text(meta_path, self._container_metadata(container))
            files.append(meta_path)
            info["meta_path"] = meta_path
        except Exception as exc:
            self.logger.warn("Не удалось записать описание контейнера: %s" % exc)
        return files, key_saved, info

    def _export_container_pfx(self, container: Container, target: str) -> bool:
        if not self.tools.certmgr:
            return False
        variants: List[str] = []
        for value in (
            container.full_name,
            container.path,
            container.internal_name,
            container.reg_path.replace(" [32-bit]", "") if container.reg_path else "",
            container.name,
        ):
            if value and value not in variants:
                variants.append(value)
        if container.path:
            prefixed = "\\\\.\\" + container.path
            if prefixed not in variants:
                variants.append(prefixed)
        for variant in variants:
            try:
                if os.path.exists(target):
                    os.remove(target)
            except Exception:
                pass
            args = [
                self.tools.certmgr,
                "-export",
                "-container",
                variant,
                "-pfx",
                "-dest",
                target,
                "-pin",
                self.password,
                "-silent",
            ]
            result = self.tools.run(args, timeout=45, sensitive=True, log_output=True)
            if result.ok and os.path.isfile(target) and os.path.getsize(target) > 0:
                return True
            if result.timed_out:
                self.logger.warn(
                    "certmgr -export -container: таймаут для %s" % variant
                )
                break
        return False

    def _container_metadata(self, container: Container) -> str:
        lines = [
            "Контейнер закрытого ключа",
            "=========================",
            "Имя: %s" % container.name,
            "Имя в контейнере: %s" % (container.internal_name or "—"),
            "Тип: %s" % container.kind_display,
            "Носитель: %s" % container.media_display,
            "Путь: %s" % (container.path or "—"),
            "Реестр: %s" % (container.reg_path or "—"),
            "Полное имя CSP: %s" % (container.full_name or "—"),
            "Источник: %s" % container.source,
            "Отпечаток сертификата: %s" % (container.thumbprint or "—"),
            "Субъект: %s" % (container.subject or "—"),
            "Действителен до: %s" % format_dt(container.not_after),
            "Статус: %s" % container.status,
            "Сертификат найден в Windows: %s" % container.cert_display,
            "Примечание: %s" % container.note,
            "",
        ]
        return "\r\n".join(lines)

    def _container_manifest_row(
        self, container: Container, files: List[str], key_saved: bool
    ) -> Dict[str, str]:
        return {
            "Тип": "Контейнер",
            "Имя": container.name,
            "Отпечаток": container.thumbprint,
            "Субъект": container.subject,
            "Издатель": "",
            "Действителен до": format_dt(container.not_after),
            "Расположение": container.location_display,
            "Тип контейнера": container.kind_display,
            "Носитель": container.media_display,
            "Путь": container.path or container.reg_path or "",
            "Файлы резервной копии": "; ".join(files),
            "Статус": "ключ сохранён" if key_saved else "ключ НЕ сохранён",
            "Примечание": container.note,
        }

    def _container_object(
        self,
        container: Container,
        files: List[str],
        key_saved: bool,
        info: Dict[str, str],
        staging: str,
    ) -> Dict[str, object]:
        directory = info.get("dir_path", "")
        pfx = info.get("pfx_path", "")
        reg = info.get("reg_path", "")
        return {
            "key": container.key,
            "name": container.name,
            "kind": container.kind,
            "media": container.media,
            "path": container.path or "",
            "reg_path": container.reg_path or "",
            "reg_hive": container.reg_hive or "",
            "reg_subkey": container.reg_subkey or "",
            "reg_wow64": int(container.reg_wow64 or 0),
            "full_name": container.full_name or "",
            "internal_name": container.internal_name or "",
            "thumbprint": container.thumbprint or "",
            "subject": container.subject or "",
            "not_after": container.not_after.isoformat() if container.not_after else "",
            "saved": bool(key_saved),
            "files": list(files),
            "dir": _archive_name(directory, staging) if directory else "",
            "pfx": _archive_name(pfx, staging) if pfx else "",
            "reg": _archive_name(reg, staging) if reg else "",
            "note": container.note,
        }

    # ------------------------------------------------------------------
    # Настройки и служебные файлы
    # ------------------------------------------------------------------
    def _backup_settings(self, reg_dir: str, summary: BackupSummary) -> None:
        exports = [
            ("CryptoPro_Settings_HKCU_64.reg", r"HKCU\Software\Crypto Pro\Settings", KEY_WOW64_64KEY),
            ("CryptoPro_Settings_HKCU_32.reg", r"HKCU\Software\Crypto Pro\Settings", KEY_WOW64_32KEY),
            ("CryptoPro_Settings_HKLM_64.reg", r"HKLM\SOFTWARE\Crypto Pro\Settings", KEY_WOW64_64KEY),
            ("CryptoPro_Settings_HKLM_32.reg", r"HKLM\SOFTWARE\Crypto Pro\Settings", KEY_WOW64_32KEY),
        ]
        for filename, reg_path, wow in exports:
            self._check_cancel()
            target = os.path.join(reg_dir, filename)
            result = self.tools.reg_export(reg_path, target, wow, timeout=90)
            if result.ok and os.path.isfile(target) and os.path.getsize(target) > 0:
                summary.files += 1
                self.logger.debug("Экспортированы настройки: %s" % reg_path)
            else:
                self.logger.debug(
                    "Настройки %s не экспортированы (нет ключа или нет прав)"
                    % reg_path
                )

    def _write_manifest(self, backup_dir: str, rows: List[Dict[str, str]]) -> None:
        path = os.path.join(backup_dir, "manifest.csv")
        fields = [
            "Тип",
            "Имя",
            "Отпечаток",
            "Субъект",
            "Издатель",
            "Действителен до",
            "Расположение",
            "Тип контейнера",
            "Носитель",
            "Путь",
            "Файлы резервной копии",
            "Статус",
            "Примечание",
        ]
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, delimiter=";")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        self.logger.debug("Записан manifest.csv")

    def _write_objects(self, backup_dir: str, objects: Dict[str, object]) -> None:
        path = os.path.join(backup_dir, "objects.json")
        with open(path, "w", encoding="utf-8", newline="") as fh:
            json.dump(objects, fh, ensure_ascii=False, indent=2)
        self.logger.debug("Записан objects.json")

    def _write_password_file(self, backup_dir: str, summary: BackupSummary) -> None:
        path = os.path.join(backup_dir, "PASSWORD.txt")
        text = (
            "Пароль для PFX-файлов резервной копии\r\n"
            "=====================================\r\n\r\n"
            "%s\r\n\r\n"
            "ВНИМАНИЕ! Этот файл содержит пароль к закрытым ключам.\r\n"
            "Храните резервную копию в защищённом месте и не передавайте пароль\r\n"
            "по незащищённым каналам. После восстановления удалите этот файл.\r\n"
            % summary.password
        )
        self._write_text(path, text)
        summary.files += 1

    def _write_readme(
        self,
        backup_dir: str,
        summary: BackupSummary,
        cert_count: int,
        container_count: int,
    ) -> None:
        text = """CryptoCleaner — резервная копия
===============================

Дата создания: {date}
Файл резервной копии: {path}
Сертификатов: {certs}
Контейнеров: {containers}
Файлов внутри архива: {files}
Ошибок: {failures}
Закрытых ключей в PFX: {keys_exported}
Ключей не экспортировано (неэкспортируемые): {keys_missing}

Это один файл *.ccbackup — обычный ZIP-архив. Его можно открыть
любым архиватором (7-Zip, WinRAR, проводником Windows).

Структура резервной копии
-------------------------
certificates/  — сертификаты (.cer), закрытые ключи (.pfx) и описания (.txt)
containers/    — копии файловых контейнеров и PFX контейнеров
registry/      — экспорт ключей реестра (.reg)
manifest.csv   — полный список объектов и путей
objects.json   — данные для автоматического восстановления
PASSWORD.txt   — пароль для PFX (храните отдельно!)
log_copy.log   — копия журнала работы

Восстановление в программе
--------------------------
1. Запустите CryptoCleaner.
2. Нажмите «Восстановить из копии».
3. Выберите файл *.ccbackup.
4. Отметьте сертификаты (и при необходимости контейнеры).
5. Нажмите «Восстановить выбранное».

Восстановление вручную
----------------------
1. Публичный сертификат (.cer):
   - двойной щелчок → «Установить сертификат»;
   - или в командной строке:
       certutil -addstore -user My файл.cer
       certutil -addstore My файл.cer        (для хранилища компьютера, от администратора)
       certutil -addstore CA файл.cer
       certutil -addstore Root файл.cer

2. Сертификат с закрытым ключом (.pfx):
   - двойной щелчок → «Импорт»;
   - или:
       certmgr -install -pfx -file файл.pfx -pin <пароль> -store uMy
       certmgr -install -pfx -file файл.pfx -pin <пароль> -store mMy
   Пароль указан в PASSWORD.txt.
   ВНИМАНИЕ: если ключ КриптоПро неэкспортируемый, PFX содержит только
   сертификат без закрытого ключа. В этом случае восстанавливайте контейнер
   из папки containers или registry (см. ниже).

3. Файловые контейнеры:
   Скопируйте папку из containers/<имя> обратно по пути, указанному
   в manifest.csv (столбец «Путь»). После копирования контейнер снова
   появится в КриптоПро CSP.

4. Контейнеры в реестре:
   Импортируйте соответствующий .reg-файл из папки registry
   (двойной щелчок). Для ветки HKLM запускайте от имени администратора.
   После импорта перезапустите КриптоПро CSP или компьютер.

Важно
-----
- Сертификат считается сохранённым только при наличии .cer или PFX с ключом.
- Контейнер считается сохранённым только тогда, когда скопирован каталог
  с header.key, экспортирована ветка реестра или PFX содержит закрытый ключ.
  Если ключевые данные сохранить не удалось, программа не удаляет контейнер.
- Резервная копия содержит закрытые ключи. Ограничьте доступ к файлу.
- После успешного восстановления удалите PASSWORD.txt из архива.
- Если сертификат был в хранилище компьютера (LocalMachine), для
  восстановления нужны права администратора.

© Алексей Мармеладов, 2026 — https://github.com/AMarmeladov
""".format(
            date=datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            path=summary.path,
            certs=cert_count,
            containers=container_count,
            files=summary.files,
            failures=summary.failures,
            keys_exported=summary.keys_exported,
            keys_missing=summary.keys_missing,
        )
        self._write_text(os.path.join(backup_dir, "README.txt"), text)
        summary.files += 1

    def _walk_files(self, root: str) -> List[str]:
        result: List[str] = []
        for current, _dirs, files in os.walk(root):
            for name in files:
                result.append(os.path.join(current, name))
        return result
