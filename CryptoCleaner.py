#!/usr/bin/env python3
"""CryptoCleaner — очистка сертификатов и контейнеров КриптоПро CSP.

Запуск без параметров открывает графический интерфейс.
Консольные режимы:
    python CryptoCleaner.py --scan
    python CryptoCleaner.py --scan --json
    python CryptoCleaner.py --delete-expired --yes
    python CryptoCleaner.py --delete-expired --delete-orphans --no-backup --yes

Программа не удаляет ничего без явного подтверждения. Перед удалением
предлагается резервная копия, которая проверяется на восстановимость;
успех фиксируется только после проверки. Удаление без копии требует
ввода контрольного слова. Отзыв сертификатов проверяется через
CertVerifyRevocation; при недоступности CRL/OCSP статус — «неизвестно».
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime


def _base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _prepare_imports() -> str:
    base = _base_dir()
    if base not in sys.path:
        sys.path.insert(0, base)
    return base


def _json_cert(cert) -> dict:
    return {
        "thumbprint": cert.thumbprint,
        "name": cert.display_name,
        "subject": cert.subject,
        "issuer": cert.issuer,
        "not_before": cert.not_before.isoformat() if cert.not_before else None,
        "not_after": cert.not_after.isoformat() if cert.not_after else None,
        "status": cert.status,
        "expired": cert.is_expired,
        "date_known": cert.date_known,
        "has_private_key": cert.has_private_key,
        "revocation": cert.revocation,
        "revocation_reason": cert.revocation_reason,
        "revocation_note": cert.revocation_note,
        "crl_urls": list(cert.crl_urls),
        "ocsp_urls": list(cert.ocsp_urls),
        "locations": [loc.code for loc in cert.locations],
        "containers": [c.name for c in cert.containers],
    }


def _json_container(container) -> dict:
    return {
        "key": container.key,
        "name": container.name,
        "kind": container.kind,
        "media": container.media,
        "path": container.path,
        "registry": container.reg_path,
        "full_name": container.full_name,
        "internal_name": container.internal_name,
        "status": container.status,
        "expired": container.is_expired,
        "orphan": container.orphan,
        "date_known": container.date_known,
        "info_known": container.info_known,
        "thumbprint": container.thumbprint,
        "subject": container.subject,
        "cert_found": container.cert_found,
        "cert_display": container.cert_display,
        "revocation": container.revocation,
        "revocation_reason": container.revocation_reason,
        "revocation_note": container.revocation_note,
        "note": container.note,
    }


def _print_summary(result, stream=None) -> None:
    import sys

    stream = stream or sys.stdout
    counts = result.counts
    print("", file=stream)
    print("Результат сканирования (%.1f с):" % result.duration, file=stream)
    print("  сертификатов: %d" % counts.get("cert_total", 0), file=stream)
    print("    просрочено: %d" % counts.get("cert_expired", 0), file=stream)
    print("    дата неизвестна: %d" % counts.get("cert_unknown", 0), file=stream)
    print("    с закрытым ключом: %d" % counts.get("cert_with_key", 0), file=stream)
    print("    отозвано: %d" % counts.get("cert_revoked", 0), file=stream)
    print(
        "    не отозвано: %d" % counts.get("cert_not_revoked", 0),
        file=stream,
    )
    print(
        "    отзыв неизвестен: %d"
        % counts.get("cert_revocation_unknown", 0),
        file=stream,
    )
    if counts.get("cert_revocation_not_checked", 0):
        print(
            "    отзыв не проверялся: %d"
            % counts.get("cert_revocation_not_checked", 0),
            file=stream,
        )
    print("  контейнеров: %d" % counts.get("cont_total", 0), file=stream)
    print("    в реестре: %d" % counts.get("cont_registry", 0), file=stream)
    print("    файловых: %d" % counts.get("cont_file", 0), file=stream)
    print("    на USB: %d" % counts.get("cont_usb", 0), file=stream)
    print("    просрочено: %d" % counts.get("cont_expired", 0), file=stream)
    print("    осиротевших: %d" % counts.get("cont_orphan", 0), file=stream)
    print("    без данных: %d" % counts.get("cont_unknown", 0), file=stream)
    if result.errors:
        print("  предупреждений: %d" % len(result.errors), file=stream)


def _print_objects(certificates, containers, stream=None) -> None:
    import sys

    stream = stream or sys.stdout
    revoked = [c for c in certificates if c.revocation == "revoked"]
    if revoked:
        print("", file=stream)
        print("ОТОЗВАННЫЕ сертификаты:", file=stream)
        for cert in revoked:
            print(
                "  %s  %s  (%s)"
                % (
                    cert.thumbprint,
                    cert.display_name,
                    cert.revocation_display,
                ),
                file=stream,
            )
    expired = [c for c in certificates if c.is_expired]
    if expired:
        print("", file=stream)
        print("Просроченные сертификаты:", file=stream)
        for cert in expired:
            print(
                "  %s  %s  (%s)"
                % (cert.thumbprint, cert.display_name, cert.source_display),
                file=stream,
            )
    problems = [c for c in containers if c.is_problem]
    if problems:
        print("", file=stream)
        print("Проблемные контейнеры:", file=stream)
        for container in problems:
            print(
                "  %s  %s  %s"
                % (
                    container.name,
                    container.status,
                    container.location_display,
                ),
                file=stream,
            )


def _confirm(prompt: str, stream=None) -> bool:
    import sys

    stream = stream or sys.stdout
    try:
        print(prompt + " [yes/no]: ", end="", file=stream, flush=True)
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("yes", "y", "да", "д")


def _confirm_word(word: str, prompt: str, stream=None) -> bool:
    """Запросить точный ввод контрольного слова."""
    import sys

    stream = stream or sys.stdout
    try:
        print(prompt + ": ", end="", file=stream, flush=True)
        answer = input().strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == word


def _run_cli(args, base_dir: str) -> int:
    from cryptocleaner.backup import (
        BackupCancelled,
        BackupManager,
        collect_backup_containers,
    )
    from cryptocleaner.deleter import DeleteCancelled, Deleter
    from cryptocleaner.logger import Logger, resolve_log_path
    from cryptocleaner.scanner import ScanCancelled, Scanner
    from cryptocleaner.tools import ToolRunner

    out = sys.stderr if args.json else sys.stdout

    def say(text: str = "") -> None:
        print(text, file=out, flush=True)

    log_path, note = resolve_log_path(base_dir, args.log)
    logger = Logger(
        log_path, console=True, level="INFO", console_stream=out
    )
    if note:
        logger.warn(note)
    logger.info("CryptoCleaner: консольный режим")
    tools = ToolRunner(logger)
    tools.log_environment()

    def progress(text: str, current: int, total: int) -> None:
        if total > 0:
            print(
                "\r%s (%d/%d)" % (text, current, total),
                end="",
                file=out,
                flush=True,
            )
        else:
            print("\r%s" % text, end="", file=out, flush=True)

    scanner = Scanner(
        logger,
        tools,
        progress=progress,
        check_revocation=not args.no_revocation,
    )
    try:
        result = scanner.scan_all()
    except ScanCancelled:
        say("\nСканирование отменено.")
        logger.close()
        return 130
    except KeyboardInterrupt:
        say("\nСканирование прервано.")
        logger.close()
        return 130
    say("")
    _print_summary(result, stream=out)
    if args.json:
        payload = {
            "generated": datetime.now().isoformat(),
            "duration": result.duration,
            "counts": result.counts,
            "certificates": [_json_cert(c) for c in result.certificates],
            "containers": [_json_container(c) for c in result.containers],
            "errors": result.errors,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)
    else:
        _print_objects(result.certificates, result.containers, stream=out)

    if not (args.delete_expired or args.delete_orphans):
        logger.close()
        return 0

    certs = []
    if args.delete_expired:
        certs = [c for c in result.certificates if c.is_expired]
    containers = []
    for container in result.containers:
        if args.delete_expired and container.is_expired:
            containers.append(container)
        elif args.delete_orphans and container.orphan is True:
            containers.append(container)

    if not certs and not containers:
        say("\nНечего удалять: под заданные условия объекты не найдены.")
        logger.close()
        return 0

    say("")
    say("К удалению:")
    say("  сертификатов: %d" % len(certs))
    say("  контейнеров: %d" % len(containers))
    if not args.yes and not _confirm("Удалить перечисленные объекты?", stream=out):
        say("Отменено пользователем.")
        logger.close()
        return 0

    backup = None
    if not args.no_backup:
        try:
            manager = BackupManager(logger, tools, base_dir=base_dir)
            backup = manager.create_backup(
                certs,
                collect_backup_containers(certs, containers),
                log_path=logger.path,
            )
        except BackupCancelled:
            say("Создание резервной копии отменено. Удаление остановлено.")
            logger.close()
            return 130
        say("")
        say("Резервная копия: %s" % backup.path)
        say(
            "  сертификатов: %d, контейнеров: %d, файлов: %d, ошибок: %d, "
            "ключей в PFX: %d, не экспортировано: %d"
            % (
                backup.certs,
                backup.containers,
                backup.files,
                backup.failures,
                backup.keys_exported,
                backup.keys_missing,
            )
        )
        say(
            "  проверка восстановимости: %s"
            % ("пройдена" if backup.verified else "НЕ пройдена")
        )
        for text in backup.verification_messages:
            say("  - %s" % text)
        if backup.failures or backup.unrestorable:
            say("")
            say(
                "Резервная копия не подтверждена. Удаление остановлено, "
                "чтобы не потерять данные."
            )
            if backup.unrestorable:
                say("Не гарантируется восстановление:")
                for text in backup.unrestorable:
                    say("  - %s" % text)
            logger.close()
            return 2
    else:
        say("")
        say("ВНИМАНИЕ: резервная копия отключена (--no-backup).")
        say("Удалённые сертификаты и закрытые ключи восстановить будет нельзя.")
        if not _confirm_word(
            "УДАЛИТЬ",
            "Для продолжения введите слово УДАЛИТЬ",
            stream=out,
        ):
            say("Отменено: контрольное слово не введено.")
            logger.close()
            return 0

    deleter = Deleter(logger, tools, progress=progress)
    try:
        results = deleter.delete_all(certs, containers)
    except (DeleteCancelled, KeyboardInterrupt):
        say("\nУдаление прервано.")
        logger.close()
        return 130
    say("")
    success = 0
    for item in results:
        if item.success:
            success += 1
        say(
            "  [%s] %s: %s — %s"
            % (
                "OK" if item.success else "ОШИБКА",
                item.kind,
                item.name,
                item.message,
            )
        )
    failed = len(results) - success
    say("")
    say("Итого: успешно %d, ошибок %d." % (success, failed))
    if backup is not None:
        say("Резервная копия: %s" % backup.path)
    logger.close()
    return 0 if failed == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CryptoCleaner — очистка сертификатов и контейнеров КриптоПро CSP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Без параметров открывается графический интерфейс.\n"
            "Перед удалением всегда предлагается резервная копия."
        ),
    )
    parser.add_argument(
        "--scan", action="store_true", help="только сканировать и показать отчёт"
    )
    parser.add_argument(
        "--json", action="store_true", help="вывести результат в JSON"
    )
    parser.add_argument(
        "--delete-expired",
        action="store_true",
        help="удалить просроченные сертификаты и контейнеры",
    )
    parser.add_argument(
        "--delete-orphans",
        action="store_true",
        help="удалить осиротевшие контейнеры (без сертификата)",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="не создавать резервную копию (не рекомендуется)",
    )
    parser.add_argument(
        "--no-revocation",
        action="store_true",
        help="не проверять отзыв сертификатов через CRL/OCSP",
    )
    parser.add_argument(
        "--yes", action="store_true", help="не запрашивать подтверждение"
    )
    parser.add_argument(
        "--log", default="", help="путь к файлу журнала"
    )
    parser.add_argument(
        "--version", action="version", version="CryptoCleaner 2.2.0"
    )
    return parser


def main(argv=None) -> int:
    base_dir = _prepare_imports()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = build_parser()
    args = parser.parse_args(argv)

    cli_mode = bool(
        args.scan
        or args.delete_expired
        or args.delete_orphans
        or args.json
        or args.log
    )
    if not cli_mode:
        try:
            from cryptocleaner.ui import run_gui
        except Exception as exc:
            print("Не удалось запустить графический интерфейс: %s" % exc)
            print("Проверьте, что установлен Python с поддержкой Tkinter.")
            return 1
        return run_gui(base_dir=base_dir)

    try:
        return _run_cli(args, base_dir)
    except KeyboardInterrupt:
        print("\nПрервано пользователем.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
