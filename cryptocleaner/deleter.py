"""Удаление сертификатов и контейнеров с проверкой результата.

Главный принцип: успех фиксируется только после повторного чтения
хранилища/каталога/реестра. Ошибка доступа никогда не считается успехом.
"""
from __future__ import annotations

import os
import shutil
import stat
import winreg
from typing import List, Optional, Tuple

from . import winapi
from .model import Certificate, Container, OperationResult
from .scanner import HIVES
from .tools import KEY_WOW64_32KEY, KEY_WOW64_64KEY, ToolRunner


class DeleteCancelled(Exception):
    pass


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        code = getattr(exc, "winerror", None)
        if code:
            return "%s (код %d)" % (exc.strerror or str(exc), code)
        return exc.strerror or str(exc)
    return str(exc)


def _on_rm_error(func, path, exc_info) -> None:
    """Снять атрибут «только чтение» и повторить удаление."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        raise


class Deleter:
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

    # ------------------------------------------------------------------
    # Служебные
    # ------------------------------------------------------------------
    def _check_cancel(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise DeleteCancelled()

    def _report(self, text: str, current: int = 0, total: int = 0) -> None:
        if self.progress:
            try:
                self.progress(text, current, total)
            except Exception:
                pass

    def _store_contains(
        self, store_name: str, location: str, thumbprint: str
    ) -> Tuple[Optional[bool], str]:
        """True/False — есть ли сертификат; None — хранилище недоступно."""
        try:
            handle = winapi.open_store(store_name, location, readonly=True)
        except OSError as exc:
            return None, _error_text(exc)
        winapi.close_store(handle)
        try:
            items = winapi.enum_certificates(store_name, location)
        except Exception as exc:
            return None, _error_text(exc)
        for item in items:
            if item.get("thumbprint") == thumbprint:
                return True, ""
        return False, ""

    def _reg_key_state(self, hive_name: str, subkey: str, wow: int) -> str:
        """'present' | 'absent' | 'unknown' (нет доступа / неизвестная ветка)."""
        hive = HIVES.get(hive_name)
        if hive is None:
            return "unknown"
        if hive_name == "HKU":
            # Если улей пользователя не загружен, отсутствие ключа ничего
            # не доказывает: это не успешное удаление.
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

    def _path_state(self, path: str) -> str:
        """'present' | 'absent' | 'unknown'.

        Отсутствие буквы диска, недоступный родительский каталог или отказ
        в доступе не должны выглядеть как успешное удаление.
        """
        if not path:
            return "unknown"
        absolute = os.path.abspath(path)
        drive = os.path.splitdrive(absolute)[0]
        if drive:
            root = drive + os.sep
            try:
                if not os.path.isdir(root):
                    return "unknown"
            except OSError:
                return "unknown"
        try:
            os.lstat(absolute)
            return "present"
        except FileNotFoundError:
            pass
        except OSError:
            return "unknown"
        parent = os.path.dirname(absolute.rstrip("\\/"))
        if parent:
            try:
                os.listdir(parent)
            except OSError:
                return "unknown"
        return "absent"

    def _reg_subkeys(self, hive, subkey: str, wow: int) -> List[str]:
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

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------
    def delete_all(
        self,
        certificates: List[Certificate],
        containers: List[Container],
    ) -> List[OperationResult]:
        """Удалить контейнеры, затем сертификаты. Вернуть отчёты."""
        results: List[OperationResult] = []
        total = len(containers) + len(certificates)
        current = 0
        for container in containers:
            self._check_cancel()
            current += 1
            self._report(
                "Удаление контейнера: %s" % container.name, current, total
            )
            results.append(self.delete_container(container))
        for cert in certificates:
            self._check_cancel()
            current += 1
            self._report(
                "Удаление сертификата: %s" % cert.display_name, current, total
            )
            results.append(self.delete_certificate(cert))
        self._report("Удаление завершено", total, total)
        return results

    # ------------------------------------------------------------------
    # Сертификаты
    # ------------------------------------------------------------------
    def delete_certificate(self, cert: Certificate) -> OperationResult:
        result = OperationResult(
            kind="Сертификат",
            name=cert.display_name,
            success=False,
            target_key=cert.key,
        )
        if not cert.locations:
            result.message = "Нет данных о расположении сертификата"
            self.logger.error(
                "Сертификат %s: %s" % (cert.thumbprint, result.message)
            )
            return result

        result.details.append("Отпечаток: %s" % cert.thumbprint)
        unresolved = 0
        for location in cert.locations:
            self._check_cancel()
            present, error = self._store_contains(
                location.store_name, location.location, cert.thumbprint
            )
            if present is None:
                result.details.append(
                    "%s: хранилище недоступно (%s)" % (location.display, error)
                )
                unresolved += 1
                continue
            if not present:
                result.details.append(
                    "%s: сертификат уже отсутствует" % location.display
                )
                continue

            removed = self._delete_cert_from_location(cert, location, result)
            present_after, error_after = self._store_contains(
                location.store_name, location.location, cert.thumbprint
            )
            if present_after is None:
                result.details.append(
                    "%s: не удалось проверить удаление (%s)"
                    % (location.display, error_after)
                )
                unresolved += 1
                continue
            if present_after:
                result.details.append(
                    "%s: сертификат остался в хранилище" % location.display
                )
                self.logger.error(
                    "Не удалось удалить сертификат %s из %s"
                    % (cert.thumbprint, location.display)
                )
            else:
                result.details.append(
                    "%s: удалён и проверен" % location.display
                )
                self.logger.ok(
                    "Сертификат %s удалён из %s"
                    % (cert.thumbprint, location.display)
                )

        if unresolved:
            result.success = False
            result.message = (
                "Не удалось подтвердить удаление из %d расположений" % unresolved
            )
        else:
            remaining = 0
            for location in cert.locations:
                present, _error = self._store_contains(
                    location.store_name, location.location, cert.thumbprint
                )
                if present is not False:
                    remaining += 1
            result.success = remaining == 0
            result.message = (
                "Сертификат удалён из всех хранилищ"
                if result.success
                else "Сертификат остался в %d расположениях" % remaining
            )
        if result.success:
            self.logger.ok(
                "Сертификат %s: %s" % (cert.thumbprint, result.message)
            )
        else:
            self.logger.error(
                "Сертификат %s: %s" % (cert.thumbprint, result.message)
            )
        return result

    def _delete_cert_from_location(
        self, cert: Certificate, location, result: OperationResult
    ) -> bool:
        """Попробовать три способа. Возвращает True, если хотя бы один отработал."""
        # 1. CryptoAPI
        try:
            deleted = winapi.delete_certificate(
                location.store_name, location.location, cert.thumbprint
            )
            if deleted:
                result.methods.append(
                    "CryptoAPI: %s (%d)" % (location.display, deleted)
                )
                return True
            result.details.append(
                "CryptoAPI: %s — контекст не найден" % location.display
            )
        except Exception as exc:
            result.details.append(
                "CryptoAPI: %s — %s" % (location.display, _error_text(exc))
            )

        # 2. certmgr КриптоПро
        if self.tools.certmgr:
            run = self.tools.run(
                [
                    self.tools.certmgr,
                    "-delete",
                    "-store",
                    location.code,
                    "-thumbprint",
                    cert.thumbprint,
                    "-silent",
                ],
                timeout=30,
                log_output=True,
            )
            if run.ok:
                result.methods.append("certmgr: %s" % location.display)
                return True
            result.details.append(
                "certmgr: %s — %s"
                % (
                    location.display,
                    "таймаут" if run.timed_out else (run.error or "код %d" % run.exit_code),
                )
            )

        # 3. certutil
        if self.tools.certutil:
            args = [self.tools.certutil, "-delstore"]
            if location.location == "CurrentUser":
                args.append("-user")
            args += [location.store_name, cert.thumbprint]
            run = self.tools.run(args, timeout=30, log_output=True)
            if run.ok:
                result.methods.append("certutil: %s" % location.display)
                return True
            result.details.append(
                "certutil: %s — %s"
                % (
                    location.display,
                    "таймаут" if run.timed_out else (run.error or "код %d" % run.exit_code),
                )
            )
        return False

    # ------------------------------------------------------------------
    # Контейнеры
    # ------------------------------------------------------------------
    def delete_container(self, container: Container) -> OperationResult:
        result = OperationResult(
            kind="Контейнер",
            name=container.name,
            success=False,
            target_key=container.key,
        )
        result.details.append("Тип: %s" % container.kind_display)
        result.details.append("Расположение: %s" % container.location_display)

        if container.kind == "Registry":
            self._delete_registry_container(container, result)
            if container.reg_hive and container.reg_subkey:
                state = self._reg_key_state(
                    container.reg_hive,
                    container.reg_subkey,
                    container.reg_wow64,
                )
            else:
                state = "unknown"
            if state == "absent":
                result.success = True
                result.message = "Ключ реестра удалён и проверен"
                self.logger.ok(
                    "Контейнер %s: %s" % (container.name, result.message)
                )
            elif state == "present":
                result.message = "Ключ реестра остался (нет прав или ошибка)"
                self.logger.error(
                    "Контейнер %s: %s" % (container.name, result.message)
                )
            else:
                result.message = (
                    "Не удалось проверить удаление ключа реестра (нет доступа)"
                )
                self.logger.error(
                    "Контейнер %s: %s" % (container.name, result.message)
                )
            return result

        if container.kind == "File":
            self._delete_file_container(container, result)
            state = self._path_state(container.path or "")
            if state == "absent":
                result.success = True
                result.message = "Каталог контейнера удалён и проверен"
                self.logger.ok(
                    "Контейнер %s: %s" % (container.name, result.message)
                )
            elif state == "present":
                result.message = "Каталог контейнера остался (занят или нет прав)"
                self.logger.error(
                    "Контейнер %s: %s" % (container.name, result.message)
                )
            else:
                result.message = (
                    "Не удалось проверить удаление каталога "
                    "(носитель недоступен или нет прав)"
                )
                self.logger.error(
                    "Контейнер %s: %s" % (container.name, result.message)
                )
            return result

        # Неизвестное расположение: пробуем средства КриптоПро, но
        # подтвердить удаление нечем — успех не заявляем.
        self._delete_via_crypto(container, result)
        result.message = (
            "Расположение контейнера неизвестно; удаление не подтверждено"
        )
        result.details.append(
            "Проверьте контейнер в КриптоПро CSP вручную."
        )
        self.logger.error("Контейнер %s: %s" % (container.name, result.message))
        return result

    # -------------------------- реестр --------------------------------
    def _delete_registry_container(
        self, container: Container, result: OperationResult
    ) -> None:
        if not container.reg_hive or not container.reg_subkey:
            result.details.append(
                "Неизвестна ветка реестра, удаление невозможно"
            )
            return

        hive = HIVES.get(container.reg_hive)
        if hive is None:
            result.details.append("Неизвестная ветка: %s" % container.reg_hive)
            return

        try:
            self._delete_reg_tree(
                hive, container.reg_subkey, container.reg_wow64
            )
            result.methods.append("winreg.DeleteKeyEx")
            result.details.append("Ветка реестра удалена через winreg")
            return
        except Exception as exc:
            result.details.append("winreg: %s" % _error_text(exc))

        if self.tools.reg:
            path = container.reg_hive + "\\" + container.reg_subkey
            args = [self.tools.reg, "delete", path, "/f"]
            if container.reg_wow64 == KEY_WOW64_32KEY:
                args.append("/reg:32")
            elif container.reg_wow64 == KEY_WOW64_64KEY:
                args.append("/reg:64")
            run = self.tools.run(args, timeout=60, log_output=True)
            if run.ok:
                result.methods.append("reg.exe delete")
                result.details.append("Ветка реестра удалена через reg.exe")
            else:
                result.details.append(
                    "reg.exe: %s"
                    % ("таймаут" if run.timed_out else (run.error or "код %d" % run.exit_code))
                )

    def _delete_reg_tree(self, hive, subkey: str, wow: int) -> None:
        for child in self._reg_subkeys(hive, subkey, wow):
            self._delete_reg_tree(hive, subkey + "\\" + child, wow)
        winreg.DeleteKeyEx(hive, subkey, wow, 0)

    # -------------------------- файлы ---------------------------------
    def _delete_file_container(
        self, container: Container, result: OperationResult
    ) -> None:
        path = container.path or ""
        if not path:
            result.details.append("Неизвестен путь контейнера")
            return
        state = self._path_state(path)
        if state == "absent":
            result.details.append("Каталог уже отсутствует: %s" % path)
            return
        if state == "unknown":
            result.details.append(
                "Каталог недоступен (носитель не подключён или нет прав): %s"
                % path
            )
            return

        try:
            shutil.rmtree(path, onerror=_on_rm_error)
            result.methods.append("Удаление каталога")
            result.details.append("Каталог удалён: %s" % path)
            return
        except Exception as exc:
            result.details.append("Удаление каталога: %s" % _error_text(exc))

        # Каталог занят — одна попытка средствами КриптоПро, затем повтор.
        self._delete_via_crypto(container, result)
        try:
            if self._path_state(path) == "present":
                shutil.rmtree(path, onerror=_on_rm_error)
                result.methods.append("Повторное удаление каталога")
                result.details.append("Каталог удалён после КриптоПро: %s" % path)
        except Exception as exc:
            result.details.append(
                "Повторное удаление каталога: %s" % _error_text(exc)
            )

    # -------------------------- КриптоПро -----------------------------
    def _container_variants(self, container: Container) -> List[str]:
        variants: List[str] = []

        def add(value: Optional[str]) -> None:
            if value and value not in variants:
                variants.append(value)

        add(container.full_name)
        if container.kind == "Registry":
            add("REGISTRY\\" + container.name)
        add(container.path)
        if container.path:
            add("\\\\.\\" + container.path)
        add(container.internal_name)
        add(container.reg_path.replace(" [32-bit]", "") if container.reg_path else "")
        add(container.name)
        return variants

    def _delete_via_crypto(
        self, container: Container, result: OperationResult
    ) -> None:
        variants = self._container_variants(container)
        if self.tools.certmgr:
            for variant in variants:
                run = self.tools.run(
                    [
                        self.tools.certmgr,
                        "-delete",
                        "-container",
                        variant,
                        "-silent",
                    ],
                    timeout=15,
                    log_output=True,
                )
                if run.ok:
                    result.methods.append("certmgr -delete -container")
                    result.details.append(
                        "КриптоПро: контейнер удалён (%s)" % variant
                    )
                    return
        if self.tools.csptest:
            for variant in variants:
                run = self.tools.run(
                    [
                        self.tools.csptest,
                        "-keyset",
                        "-deletekeyset",
                        "-container",
                        variant,
                        "-silent",
                    ],
                    timeout=15,
                    log_output=True,
                )
                if run.ok:
                    result.methods.append("csptest -deletekeyset")
                    result.details.append(
                        "КриптоПро: ключевой набор удалён (%s)" % variant
                    )
                    return
        result.details.append(
            "Средства КриптоПро не подтвердили удаление контейнера"
        )
