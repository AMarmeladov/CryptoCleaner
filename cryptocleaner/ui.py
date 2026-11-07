"""Графический интерфейс CryptoCleaner (Tkinter, Python 3.8+).

Интерфейс рассчитан на высокое масштабирование Windows (100–300 %):
все размеры пересчитываются из DPI, шрифты задаются в пикселях, поэтому
текст не «заезжает» на соседние элементы.
"""
from __future__ import annotations

import getpass
import ctypes
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Tuple

from . import winapi
from .backup import (
    BACKUP_EXTENSION,
    BackupCancelled,
    BackupManager,
    choose_backup_root,
    collect_backup_containers,
)
from .deleter import DeleteCancelled, Deleter
from .model import (
    BackupSummary,
    Certificate,
    Container,
    OperationResult,
    format_dt,
)
from .restore import (
    BackupContents,
    BackupReader,
    RestoreCancelled,
    RestoreManager,
)
from .scanner import ScanCancelled, Scanner, ScanResult
from .tools import ToolRunner

APP_TITLE = "CryptoCleaner — сертификаты и контейнеры КриптоПро"
APP_VERSION = "2.1.2"
AUTHOR = "Алексей Мармеладов"
AUTHOR_YEAR = "2026"
AUTHOR_URL = "https://github.com/AMarmeladov"

# ---------------------------------------------------------------------------
# Палитра из 1794059231.png: глубокий синий, яркий голубой, лёд и серебро
# ---------------------------------------------------------------------------
NAVY = "#041A4A"
NAVY_2 = "#0A2A66"
BLUE = "#0F8FD8"
BLUE_DARK = "#0B6FAE"
CYAN = "#21C0F0"
CYAN_LIGHT = "#7FDFFF"
BG = "#EAF4FB"
BG_ALT = "#DDEBF6"
CARD = "#FFFFFF"
TEXT = "#0B1B33"
MUTED = "#4B6076"
SILVER = "#C7E1F0"
SUCCESS = "#1B7F4B"
DANGER = "#B00020"
WARNING = "#A15C00"
ORPHAN = "#7B1FA2"
LOG_BG = "#061530"
LOG_FG = "#DCEBF7"

CERT_FILTERS = [
    "Все",
    "Просроченные",
    "Действительные",
    "Дата неизвестна",
    "С закрытым ключом",
    "Отозванные",
]
CONT_FILTERS = [
    "Все",
    "Проблемные",
    "Просроченные",
    "Осиротевшие",
    "Действительные",
    "Дата неизвестна",
    "Нет данных",
]
CONT_TYPES = [
    "Все",
    "Реестр",
    "Файловые (HDD)",
    "USB/съёмные",
    "Неизвестные",
]


def _script_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(sys.argv[0]))


def _asset_dir() -> str:
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        candidate = os.path.join(base, "cryptocleaner", "assets")
        if os.path.isdir(candidate):
            return candidate
        return os.path.join(
            os.path.dirname(os.path.abspath(sys.executable)),
            "cryptocleaner",
            "assets",
        )
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


def _asset(name: str) -> str:
    return os.path.join(_asset_dir(), name)


def _registry_display(container: Container) -> str:
    """Путь реестра для показа: REGISTRY\\<имя> (ровно один обратный слэш)."""
    name = (container.name or "").strip("\\")
    return "REGISTRY\\" + name if name else "REGISTRY"


def _container_location(container: Container) -> str:
    if container.kind == "Registry":
        return _registry_display(container)
    if container.kind == "File":
        return container.path or container.full_name or container.name
    return container.full_name or container.name


def _truncate(value: str, limit: int = 160) -> str:
    value = value or ""
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _format_size(path: str) -> str:
    try:
        size = os.path.getsize(path)
    except Exception:
        return "—"
    if size >= 1024 * 1024 * 1024:
        return "%.1f ГБ" % (size / (1024.0 ** 3))
    if size >= 1024 * 1024:
        return "%.1f МБ" % (size / (1024.0 ** 2))
    if size >= 1024:
        return "%.0f КБ" % (size / 1024.0)
    return "%d Б" % size


# ---------------------------------------------------------------------------
# Окно результатов
# ---------------------------------------------------------------------------
class ResultsWindow(tk.Toplevel):
    """Окно отчёта об удалении или восстановлении."""

    def __init__(
        self,
        master: "CryptoCleanerApp",
        results: List[OperationResult],
        title: str = "Результат операции",
        subtitle: str = "",
        backup: Optional[BackupSummary] = None,
        open_path: str = "",
    ) -> None:
        super().__init__(master)
        self.title(title)
        master.place_dialog(
            self,
            master.px(1000),
            master.px(580),
            master.px(760),
            master.px(420),
        )
        self.configure(bg=BG)
        self.results = results
        self._rows: Dict[str, OperationResult] = {}
        self._master = master

        success = sum(1 for r in results if r.success)
        failed = len(results) - success

        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=master.px(14), pady=(master.px(14), master.px(4)))
        tk.Label(
            header,
            text=title,
            font=master.font(17, "bold"),
            bg=BG,
            fg=NAVY_2,
        ).pack(anchor="w")
        summary = "Успешно: %d    Ошибок: %d    Всего: %d" % (
            success,
            failed,
            len(results),
        )
        tk.Label(
            header,
            text=summary,
            font=master.font(12, "bold"),
            bg=BG,
            fg=DANGER if failed else SUCCESS,
        ).pack(anchor="w", pady=(master.px(2), 0))
        if subtitle:
            tk.Label(
                header,
                text=subtitle,
                font=master.font(11),
                bg=BG,
                fg=MUTED,
                wraplength=master.px(900),
                justify="left",
            ).pack(anchor="w", pady=(master.px(4), 0))
        if backup is not None:
            tk.Label(
                header,
                text="Файл резервной копии: %s (%s, файлов: %d, ошибок: %d)"
                % (
                    backup.path,
                    _format_size(backup.path),
                    backup.files,
                    backup.failures,
                ),
                font=master.font(11),
                bg=BG,
                fg=MUTED,
                wraplength=master.px(920),
                justify="left",
            ).pack(anchor="w", pady=(master.px(4), 0))

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=master.px(14), pady=master.px(6))
        body.rowconfigure(0, weight=3)
        body.rowconfigure(1, weight=1)
        body.columnconfigure(0, weight=1)

        columns = ("status", "kind", "name", "message", "methods")
        tree_frame = tk.Frame(body, bg=BG)
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "status": ("Результат", 105),
            "kind": ("Тип", 105),
            "name": ("Объект", 270),
            "message": ("Сообщение", 390),
            "methods": ("Способ", 200),
        }
        for key, (heading, width) in headings.items():
            tree.heading(key, text=heading)
            tree.column(
                key,
                width=master.px(width),
                anchor="w",
                stretch=key in ("name", "message"),
            )
        tree.tag_configure("ok", foreground=SUCCESS)
        tree.tag_configure("fail", foreground=DANGER)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        details_frame = tk.Frame(body, bg=BG)
        details_frame.grid(
            row=1, column=0, sticky="nsew", pady=(master.px(8), 0)
        )
        details_frame.rowconfigure(1, weight=1)
        details_frame.columnconfigure(0, weight=1)
        tk.Label(
            details_frame,
            text="Подробности",
            font=master.font(11, "bold"),
            bg=BG,
            fg=NAVY_2,
        ).grid(row=0, column=0, sticky="w")
        text = tk.Text(
            details_frame,
            height=7,
            wrap="word",
            font=master.font(11, family="Consolas"),
            bg=CARD,
            fg=TEXT,
            relief="flat",
            highlightbackground=SILVER,
            highlightthickness=1,
            padx=master.px(8),
            pady=master.px(6),
        )
        text.grid(row=1, column=0, sticky="nsew")
        dsb = ttk.Scrollbar(details_frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=dsb.set)
        dsb.grid(row=1, column=1, sticky="ns")

        for index, result in enumerate(results):
            iid = str(index)
            self._rows[iid] = result
            tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "OK" if result.success else "ОШИБКА",
                    result.kind,
                    _truncate(result.name, 90),
                    result.message,
                    "; ".join(result.methods) or "—",
                ),
                tags=("ok" if result.success else "fail",),
            )

        def on_select(_event=None) -> None:
            selection = tree.selection()
            if not selection:
                return
            result = self._rows.get(selection[0])
            if not result:
                return
            lines = [
                "%s: %s" % (result.kind, result.name),
                "Результат: %s" % ("успешно" if result.success else "ошибка"),
                "Сообщение: %s" % result.message,
                "Способы: %s" % ("; ".join(result.methods) or "—"),
                "",
                "Подробности:",
            ]
            lines.extend("  " + item for item in result.details)
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.insert("1.0", "\n".join(lines))
            text.configure(state="disabled")

        tree.bind("<<TreeviewSelect>>", on_select)

        buttons = tk.Frame(self, bg=BG)
        buttons.pack(
            fill="x",
            padx=master.px(14),
            pady=(master.px(4), master.px(14)),
        )
        ttk.Button(buttons, text="Закрыть", command=self.destroy).pack(
            side="right"
        )
        if open_path:
            ttk.Button(
                buttons,
                text="Открыть папку",
                command=lambda: master._open_path(open_path),
            ).pack(side="left")
        elif backup is not None:
            ttk.Button(
                buttons,
                text="Открыть папку резервной копии",
                command=lambda: master._open_path(backup.path),
            ).pack(side="left")
        if results:
            tree.selection_set("0")
            on_select()

        self.transient(master)
        self.lift()


# ---------------------------------------------------------------------------
# Окно выбора объектов для восстановления
# ---------------------------------------------------------------------------
class RestoreDialog(tk.Toplevel):
    def __init__(
        self,
        master: "CryptoCleanerApp",
        contents: BackupContents,
        on_restore,
    ) -> None:
        super().__init__(master)
        self.master_app = master
        self.contents = contents
        self.on_restore = on_restore
        self.title("Восстановление из резервной копии")
        master.place_dialog(
            self,
            master.px(1120),
            master.px(780),
            master.px(820),
            master.px(560),
        )
        self.configure(bg=BG)
        self._cert_rows: Dict[str, object] = {}
        self._cont_rows: Dict[str, object] = {}
        self._checked_certs = {
            cert.thumbprint for cert in contents.certificates if cert.saved
        }
        self._checked_conts: set = set()

        header = tk.Frame(self, bg=NAVY)
        header.pack(fill="x")
        inner = tk.Frame(header, bg=NAVY)
        inner.pack(
            fill="x",
            padx=master.px(18),
            pady=(master.px(12), master.px(10)),
        )
        tk.Label(
            inner,
            text="Восстановление из резервной копии",
            font=master.font(20, "bold"),
            bg=NAVY,
            fg="white",
        ).pack(anchor="w")
        tk.Label(
            inner,
            text=contents.name,
            font=master.font(12),
            bg=NAVY,
            fg="#B9DDF3",
        ).pack(anchor="w", pady=(master.px(2), 0))
        tk.Frame(self, bg=CYAN, height=master.px(3)).pack(fill="x")

        info = tk.Frame(self, bg=BG)
        info.pack(fill="x", padx=master.px(16), pady=(master.px(10), master.px(2)))
        tk.Label(
            info,
            text="Создана: %s    Пароль PFX: %s    Формат: %s"
            % (
                contents.created_display,
                "найден" if contents.password else "не найден",
                "старый (совместимый)" if contents.legacy else "CryptoCleaner",
            ),
            font=master.font(11),
            bg=BG,
            fg=MUTED,
        ).pack(anchor="w")
        if contents.warnings:
            tk.Label(
                info,
                text="; ".join(contents.warnings[:3]),
                font=master.font(10),
                bg=BG,
                fg=WARNING,
                wraplength=master.px(1000),
                justify="left",
            ).pack(anchor="w", pady=(master.px(3), 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(
            fill="both",
            expand=True,
            padx=master.px(14),
            pady=(master.px(8), master.px(4)),
        )
        self._build_cert_tab()
        self._build_cont_tab()
        self._build_buttons()

        self.transient(master)
        self.lift()
        self.grab_set()

    # ------------------------------------------------------------------
    def _build_cert_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(
            tab, text="Сертификаты (%d)" % len(self.contents.certificates)
        )
        top = tk.Frame(tab, bg=BG)
        top.pack(fill="x", padx=master_px(self, 2), pady=(master_px(self, 8), master_px(self, 4)))
        ttk.Button(
            top,
            text="Выбрать все",
            command=self._select_all_certs,
        ).pack(side="left")
        ttk.Button(
            top,
            text="Снять все",
            command=self._unselect_all_certs,
        ).pack(side="left", padx=(master_px(self, 6), 0))
        tk.Label(
            top,
            text="По умолчанию выбраны все сохранённые сертификаты.",
            font=self.master_app.font(10),
            bg=BG,
            fg=MUTED,
        ).pack(side="left", padx=(master_px(self, 12), 0))

        frame = tk.Frame(tab, bg=BG)
        frame.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        columns = ("sel", "name", "subject", "expires", "stores", "key", "status")
        tree = ttk.Treeview(
            frame, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "sel": ("✓", 40),
            "name": ("Имя / CN", 260),
            "subject": ("Субъект", 340),
            "expires": ("Действителен до", 150),
            "stores": ("Хранилища", 300),
            "key": ("Ключ", 150),
            "status": ("Статус", 120),
        }
        for key, (heading, width) in headings.items():
            tree.heading(key, text=heading)
            tree.column(
                key,
                width=self.master_app.px(width),
                anchor="center" if key in ("sel", "expires") else "w",
                stretch=key in ("name", "subject", "stores"),
            )
        tree.tag_configure("ok", foreground=SUCCESS)
        tree.tag_configure("fail", foreground=DANGER)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.cert_tree = tree
        tree.bind("<Button-1>", lambda event: self._on_click(event, tree, "cert"))
        tree.bind("<Double-1>", lambda event: self._on_double(event, tree, "cert"))
        tree.bind("<space>", lambda event: self._toggle_selected(tree, "cert"))

        for index, cert in enumerate(self.contents.certificates):
            iid = str(index)
            self._cert_rows[iid] = cert
            tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "✓" if cert.thumbprint in self._checked_certs else "",
                    _truncate(cert.name, 90),
                    _truncate(cert.subject, 140),
                    format_dt(cert.not_after),
                    _truncate(cert.location_display, 140),
                    cert.key_display,
                    cert.status_display,
                ),
                tags=("ok" if cert.saved else "fail",),
            )

    def _build_cont_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(
            tab, text="Контейнеры (%d)" % len(self.contents.containers)
        )
        top = tk.Frame(tab, bg=BG)
        top.pack(fill="x", padx=2, pady=(8, 4))
        ttk.Button(
            top,
            text="Выбрать все",
            command=self._select_all_conts,
        ).pack(side="left")
        ttk.Button(
            top,
            text="Снять все",
            command=self._unselect_all_conts,
        ).pack(side="left", padx=(6, 0))
        tk.Label(
            top,
            text="Контейнеры восстанавливаются только по явной отметке.",
            font=self.master_app.font(10),
            bg=BG,
            fg=MUTED,
        ).pack(side="left", padx=(12, 0))

        frame = tk.Frame(tab, bg=BG)
        frame.pack(fill="both", expand=True, padx=2, pady=(0, 4))
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        columns = ("sel", "name", "kind", "media", "location", "status")
        tree = ttk.Treeview(
            frame, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "sel": ("✓", 40),
            "name": ("Имя контейнера", 250),
            "kind": ("Тип", 110),
            "media": ("Носитель", 130),
            "location": ("Расположение", 430),
            "status": ("Статус", 170),
        }
        for key, (heading, width) in headings.items():
            tree.heading(key, text=heading)
            tree.column(
                key,
                width=self.master_app.px(width),
                anchor="center" if key == "sel" else "w",
                stretch=key in ("name", "location"),
            )
        tree.tag_configure("ok", foreground=SUCCESS)
        tree.tag_configure("fail", foreground=DANGER)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.cont_tree = tree
        tree.bind("<Button-1>", lambda event: self._on_click(event, tree, "cont"))
        tree.bind("<Double-1>", lambda event: self._on_double(event, tree, "cont"))
        tree.bind("<space>", lambda event: self._toggle_selected(tree, "cont"))

        for index, container in enumerate(self.contents.containers):
            iid = str(index)
            self._cont_rows[iid] = container
            tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "✓" if container.key in self._checked_conts else "",
                    _truncate(container.name, 90),
                    container.kind_display,
                    container.media_display,
                    _truncate(container.location_display, 200),
                    container.status_display,
                ),
                tags=("ok" if container.saved else "fail",),
            )

    def _build_buttons(self) -> None:
        bottom = tk.Frame(self, bg=BG)
        bottom.pack(
            fill="x",
            padx=self.master_app.px(16),
            pady=(self.master_app.px(4), self.master_app.px(12)),
        )
        self.overwrite = tk.BooleanVar(value=False)
        tk.Checkbutton(
            bottom,
            text="Перезаписывать существующие контейнеры (старые сохраняются рядом)",
            variable=self.overwrite,
            bg=BG,
            fg=TEXT,
            activebackground=BG,
            activeforeground=TEXT,
            selectcolor=CARD,
            font=self.master_app.font(11),
            anchor="w",
        ).pack(side="left")
        ttk.Button(
            bottom,
            text="Восстановить выбранное",
            style="Accent.TButton",
            command=self._do_restore,
        ).pack(side="right")
        ttk.Button(
            bottom,
            text="Отмена",
            command=self.destroy,
        ).pack(side="right", padx=(0, self.master_app.px(8)))

    # ------------------------------------------------------------------
    def _on_click(self, event, tree, kind: str) -> Optional[str]:
        if tree.identify("region", event.x, event.y) != "cell":
            return None
        if tree.identify_column(event.x) != "#1":
            return None
        iid = tree.identify_row(event.y)
        if iid:
            self._toggle_row(iid, kind)
        return "break"

    def _on_double(self, event, tree, kind: str) -> Optional[str]:
        iid = tree.identify_row(event.y)
        if iid:
            self._toggle_row(iid, kind)
        return "break"

    def _toggle_selected(self, tree, kind: str) -> str:
        for iid in tree.selection():
            self._toggle_row(iid, kind)
        return "break"

    def _toggle_row(self, iid: str, kind: str) -> None:
        if kind == "cert":
            item = self._cert_rows.get(iid)
            if not item:
                return
            if item.thumbprint in self._checked_certs:
                self._checked_certs.discard(item.thumbprint)
                mark = ""
            else:
                self._checked_certs.add(item.thumbprint)
                mark = "✓"
            self._set_mark(self.cert_tree, iid, mark)
        else:
            item = self._cont_rows.get(iid)
            if not item:
                return
            if item.key in self._checked_conts:
                self._checked_conts.discard(item.key)
                mark = ""
            else:
                self._checked_conts.add(item.key)
                mark = "✓"
            self._set_mark(self.cont_tree, iid, mark)

    def _set_mark(self, tree, iid: str, mark: str) -> None:
        try:
            values = list(tree.item(iid, "values"))
            values[0] = mark
            tree.item(iid, values=values)
        except Exception:
            pass

    def _select_all_certs(self) -> None:
        self._checked_certs = {
            cert.thumbprint for cert in self.contents.certificates
        }
        for iid, cert in self._cert_rows.items():
            self._set_mark(self.cert_tree, iid, "✓")

    def _unselect_all_certs(self) -> None:
        self._checked_certs.clear()
        for iid in self._cert_rows:
            self._set_mark(self.cert_tree, iid, "")

    def _select_all_conts(self) -> None:
        self._checked_conts = {
            container.key for container in self.contents.containers
        }
        for iid, container in self._cont_rows.items():
            self._set_mark(self.cont_tree, iid, "✓")

    def _unselect_all_conts(self) -> None:
        self._checked_conts.clear()
        for iid in self._cont_rows:
            self._set_mark(self.cont_tree, iid, "")

    def _do_restore(self) -> None:
        thumbs = [
            cert.thumbprint
            for cert in self.contents.certificates
            if cert.thumbprint in self._checked_certs
        ]
        keys = [
            container.key
            for container in self.contents.containers
            if container.key in self._checked_conts
        ]
        if not thumbs and not keys:
            messagebox.showinfo(
                "Восстановление",
                "Отметьте сертификаты и/или контейнеры для восстановления.",
                parent=self,
            )
            return
        lines = [
            "Будет восстановлено:",
            "  сертификатов: %d" % len(thumbs),
            "  контейнеров: %d" % len(keys),
            "",
            "Источник: %s" % self.contents.path,
        ]
        if not self.contents.password and any(
            cert.pfx_has_key for cert in self.contents.certificates
            if cert.thumbprint in set(thumbs)
        ):
            lines.append("")
            lines.append(
                "ВНИМАНИЕ: пароль PFX не найден. Сертификаты без ключа "
                "можно восстановить, но закрытые ключи из PFX — нет."
            )
        lines.append("")
        lines.append("Продолжить?")
        if not messagebox.askyesno(
            "Подтверждение восстановления",
            "\n".join(lines),
            icon="question",
            parent=self,
        ):
            return
        overwrite = bool(self.overwrite.get())
        self.grab_release()
        self.destroy()
        self.on_restore(self.contents, thumbs, keys, overwrite)


def master_px(dialog: RestoreDialog, value: int) -> int:
    return dialog.master_app.px(value)


# ---------------------------------------------------------------------------
# Главное окно
# ---------------------------------------------------------------------------
class CryptoCleanerApp(tk.Tk):
    def __init__(self, base_dir: str = "", log_path: str = "") -> None:
        super().__init__()
        self.base_dir = base_dir or _script_dir()
        self._init_scaling()
        self.title(APP_TITLE)
        self._apply_icon()
        self._set_initial_geometry()
        self.configure(bg=BG)
        self.option_add("*Font", self.font(12))
        self.option_add("*Menu.font", self.font(11))
        self.option_add("*TCombobox*Listbox.font", self.font(12))

        self.queue: "queue.Queue[tuple]" = queue.Queue()
        self.busy = False
        self.cancel_event = threading.Event()
        self.result: Optional[ScanResult] = None
        self.certificates: List[Certificate] = []
        self.containers: List[Container] = []
        self.checked_certs: set = set()
        self.checked_conts: set = set()
        self._cert_rows: Dict[str, Certificate] = {}
        self._cont_rows: Dict[str, Container] = {}
        self._last_backup: Optional[BackupSummary] = None
        self.user_display = winapi.get_current_user() or getpass.getuser()

        from .logger import Logger, resolve_log_path

        if not log_path:
            log_path, note = resolve_log_path(self.base_dir)
        else:
            note = ""
        self.logger = Logger(log_path, ui_callback=self._on_log)
        if note:
            self.logger.warn(note)
        self.tools = ToolRunner(self.logger)
        self.logger.info(
            "CryptoCleaner %s запущен. Каталог: %s" % (APP_VERSION, self.base_dir)
        )
        self.logger.info("Пользователь: %s" % self.user_display)
        self.tools.log_environment()
        self.logger.info(
            "Права администратора: %s"
            % ("да" if winapi.is_admin() else "нет")
        )

        self._build_style()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_queue)
        self.after(500, self._start_scan)

    # ------------------------------------------------------------------
    # Масштабирование и иконка
    # ------------------------------------------------------------------
    def _init_scaling(self) -> None:
        try:
            dpi = float(self.winfo_fpixels("1i"))
        except Exception:
            dpi = 96.0
        if dpi < 72.0 or dpi > 480.0:
            dpi = 96.0
        self.dpi = dpi
        self.scale = max(1.0, min(4.0, dpi / 96.0))
        try:
            self.tk.call("tk", "scaling", dpi / 72.0)
        except Exception:
            pass
        self._fonts: Dict[Tuple[int, str, str], tuple] = {}

    def px(self, value: int) -> int:
        return max(1, int(round(value * self.scale)))

    def font(
        self, size: int = 12, weight: str = "normal", family: str = "Segoe UI"
    ) -> tuple:
        key = (size, weight, family)
        cached = self._fonts.get(key)
        if cached is None:
            pixels = -self.px(size)
            if weight and weight != "normal":
                cached = (family, pixels, weight)
            else:
                cached = (family, pixels)
            self._fonts[key] = cached
        return cached

    def _apply_icon(self) -> None:
        """Установить иконку текущего окна и окон, созданных позже.

        Важно: ``iconphoto(True, ...)`` и ``iconbitmap(default=...)`` задают
        иконку только для окон, созданных ПОСЛЕ вызова, а текущему окну её не
        ставят. Поэтому сначала явно применяем иконку к этому окну, а затем
        задаём её как иконку по умолчанию для диалогов.
        """
        photos = []
        for name in (
            "cryptocleaner_16.png",
            "cryptocleaner_32.png",
            "cryptocleaner_64.png",
            "cryptocleaner.png",
        ):
            path = _asset(name)
            if not os.path.isfile(path):
                continue
            try:
                photos.append(tk.PhotoImage(file=path))
            except Exception:
                pass
        if photos:
            self._icon_photos = photos
            self._icon_photo = photos[-1]
            try:
                self.iconphoto(False, *photos)
            except Exception:
                pass
            try:
                self.iconphoto(True, *photos)
            except Exception:
                pass
        ico = _asset("cryptocleaner.ico")
        if os.path.isfile(ico):
            try:
                self.iconbitmap(ico)
            except Exception:
                pass
            try:
                self.iconbitmap(default=ico)
            except Exception:
                pass
        self._logo_photo = None
        try:
            desired = self.px(46)
            path = _asset("cryptocleaner.png")
            if os.path.isfile(path):
                photo = tk.PhotoImage(file=path)
                factor = max(1, int(round(256.0 / max(1, desired))))
                if factor > 1:
                    photo = photo.subsample(factor, factor)
                self._logo_photo = photo
        except Exception:
            self._logo_photo = None

    def _set_initial_geometry(self) -> None:
        width = self.px(1280)
        height = self.px(820)
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = min(width, max(self.px(900), int(screen_w * 0.94)))
        height = min(height, max(self.px(600), int(screen_h * 0.90)))
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 3)
        self.geometry("%dx%d+%d+%d" % (width, height, x, y))
        self.minsize(
            min(self.px(980), int(screen_w * 0.80)),
            min(self.px(620), int(screen_h * 0.70)),
        )

    def place_dialog(
        self,
        window: tk.Toplevel,
        width: int,
        height: int,
        min_width: int = 0,
        min_height: int = 0,
    ) -> None:
        """Разместить дочернее окно по центру родителя, не выходя за экран."""
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = max(320, min(width, int(screen_w * 0.96)))
        height = max(240, min(height, int(screen_h * 0.92)))
        try:
            parent_x = self.winfo_rootx()
            parent_y = self.winfo_rooty()
            parent_w = self.winfo_width()
            parent_h = self.winfo_height()
        except Exception:
            parent_x = parent_y = 0
            parent_w = screen_w
            parent_h = screen_h
        x = parent_x + (parent_w - width) // 2
        y = parent_y + max(0, (parent_h - height) // 3)
        x = max(0, min(x, screen_w - width))
        y = max(0, min(y, screen_h - height))
        window.geometry("%dx%d+%d+%d" % (width, height, x, y))
        if min_width or min_height:
            window.minsize(
                min(min_width or width, width),
                min(min_height or height, height),
            )

    # ------------------------------------------------------------------
    # Стили
    # ------------------------------------------------------------------
    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", font=self.font(12))
        style.configure(
            "TButton",
            font=self.font(12),
            padding=(self.px(11), self.px(6)),
            background=CARD,
            foreground=TEXT,
            bordercolor=SILVER,
            lightcolor=CARD,
            darkcolor=SILVER,
            relief="flat",
        )
        style.map(
            "TButton",
            background=[
                ("disabled", "#EDF2F6"),
                ("pressed", "#B9DDF3"),
                ("active", "#D6EAF8"),
            ],
            foreground=[("disabled", "#98A6B5")],
        )
        style.configure(
            "Accent.TButton",
            font=self.font(12, "bold"),
            background=BLUE,
            foreground="white",
            bordercolor=BLUE_DARK,
            lightcolor=BLUE,
            darkcolor=BLUE_DARK,
        )
        style.map(
            "Accent.TButton",
            background=[
                ("disabled", "#9CC9E8"),
                ("pressed", "#095C92"),
                ("active", BLUE_DARK),
            ],
            foreground=[("disabled", "#F0F7FC")],
        )
        style.configure(
            "Restore.TButton",
            font=self.font(12, "bold"),
            background=NAVY_2,
            foreground="white",
            bordercolor=NAVY,
            lightcolor=NAVY_2,
            darkcolor=NAVY,
        )
        style.map(
            "Restore.TButton",
            background=[
                ("disabled", "#7D90B5"),
                ("pressed", NAVY),
                ("active", NAVY),
            ],
            foreground=[("disabled", "#E8EEF8")],
        )
        style.configure(
            "Danger.TButton",
            font=self.font(12, "bold"),
            background=DANGER,
            foreground="white",
            bordercolor="#7A0016",
            lightcolor=DANGER,
            darkcolor="#7A0016",
        )
        style.map(
            "Danger.TButton",
            background=[
                ("disabled", "#D89AA6"),
                ("pressed", "#7A0016"),
                ("active", "#920019"),
            ],
            foreground=[("disabled", "#FBEDEF")],
        )
        style.configure("TLabel", background=BG, foreground=TEXT, font=self.font(12))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=self.font(11))
        style.configure("Card.TFrame", background=CARD)
        style.configure(
            "TCheckbutton",
            background=BG,
            foreground=TEXT,
            font=self.font(11),
        )
        style.map(
            "TCheckbutton",
            background=[("active", BG)],
            foreground=[("active", TEXT)],
        )
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            padding=(self.px(20), self.px(9)),
            font=self.font(12, "bold"),
            background=BG_ALT,
            foreground=MUTED,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", CARD)],
            foreground=[("selected", BLUE_DARK)],
        )
        style.configure(
            "Treeview",
            background=CARD,
            fieldbackground=CARD,
            foreground=TEXT,
            rowheight=self.px(26),
            font=self.font(12),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#CDEBFA")],
            foreground=[("selected", TEXT)],
        )
        style.configure(
            "Treeview.Heading",
            background=NAVY_2,
            foreground="white",
            font=self.font(11, "bold"),
            padding=(self.px(7), self.px(6)),
            relief="flat",
        )
        style.map("Treeview.Heading", background=[("active", BLUE_DARK)])
        style.configure(
            "TEntry",
            fieldbackground=CARD,
            foreground=TEXT,
            bordercolor=SILVER,
            padding=self.px(5),
            font=self.font(12),
        )
        style.configure(
            "TCombobox",
            fieldbackground=CARD,
            foreground=TEXT,
            bordercolor=SILVER,
            padding=self.px(4),
            font=self.font(12),
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", CARD)],
            foreground=[("readonly", TEXT)],
        )
        style.configure(
            "TScrollbar",
            background=BG_ALT,
            troughcolor=BG,
            bordercolor=BG,
            arrowcolor=MUTED,
        )
        style.configure(
            "TProgressbar",
            troughcolor="#D6E6F2",
            background=BLUE,
            bordercolor=BG,
            lightcolor=BLUE,
            darkcolor=BLUE_DARK,
        )
        style.configure("TPanedwindow", background=BG)

    # ------------------------------------------------------------------
    # Построение интерфейса
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        self._build_header()
        tk.Frame(self, bg=CYAN, height=self.px(3)).pack(fill="x")
        self._build_footer()
        self._build_toolbar()

        self.summary_label = tk.Label(
            self,
            text="Сканирование ещё не выполнялось",
            font=self.font(11, "bold"),
            bg=BG,
            fg=MUTED,
            anchor="w",
        )
        self.summary_label.pack(
            fill="x", padx=self.px(16), pady=(self.px(2), self.px(2))
        )

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(
            fill="both",
            expand=True,
            padx=self.px(14),
            pady=(0, self.px(6)),
        )
        self._build_cert_tab()
        self._build_cont_tab()
        self._build_log_tab()

        self.bind("<F5>", lambda _event: self._start_scan())
        self.bind("<Control-a>", self._select_all_current)

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=NAVY)
        header.pack(fill="x")
        inner = tk.Frame(header, bg=NAVY)
        inner.pack(
            fill="x",
            padx=self.px(18),
            pady=(self.px(12), self.px(11)),
        )
        if self._logo_photo is not None:
            tk.Label(
                inner,
                image=self._logo_photo,
                bg=NAVY,
                bd=0,
            ).pack(side="left", padx=(0, self.px(14)))
        title_box = tk.Frame(inner, bg=NAVY)
        title_box.pack(side="left", anchor="w")
        tk.Label(
            title_box,
            text="CryptoCleaner",
            font=self.font(26, "bold"),
            bg=NAVY,
            fg="white",
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text=(
                "Очистка сертификатов и контейнеров закрытых ключей "
                "КриптоПро CSP"
            ),
            font=self.font(12),
            bg=NAVY,
            fg="#B9DDF3",
        ).pack(anchor="w", pady=(self.px(2), 0))

        info = tk.Frame(inner, bg=NAVY)
        info.pack(side="right", anchor="e")
        admin = winapi.is_admin()
        tk.Label(
            info,
            text="Пользователь: %s" % self.user_display,
            font=self.font(12, "bold"),
            bg=NAVY,
            fg="white",
        ).pack(anchor="e")
        self.admin_label = tk.Label(
            info,
            text=(
                "Права: администратор"
                if admin
                else "Права: пользователь — хранилище компьютера ограничено"
            ),
            font=self.font(11),
            bg=NAVY,
            fg="#7EE787" if admin else "#FFD166",
        )
        self.admin_label.pack(anchor="e", pady=(self.px(2), 0))
        self.btn_elevate = tk.Button(
            info,
            text="Запустить от имени администратора",
            command=self._elevate,
            bg=CYAN,
            fg=NAVY,
            activebackground=CYAN_LIGHT,
            activeforeground=NAVY,
            disabledforeground="#6B7C93",
            relief="flat",
            bd=0,
            cursor="hand2",
            font=self.font(11, "bold"),
            padx=self.px(14),
            pady=self.px(6),
        )
        if admin:
            self.btn_elevate.configure(
                text="Права администратора",
                state="disabled",
                bg="#1B7F4B",
                fg="white",
                disabledforeground="white",
                cursor="arrow",
            )
        self.btn_elevate.pack(anchor="e", pady=(self.px(7), 0))

    def _build_toolbar(self) -> None:
        outer = tk.Frame(self, bg=BG)
        outer.pack(
            fill="x", padx=self.px(14), pady=(self.px(12), self.px(6))
        )
        card = tk.Frame(
            outer,
            bg=CARD,
            highlightbackground=SILVER,
            highlightthickness=1,
        )
        card.pack(fill="x")
        toolbar = tk.Frame(card, bg=CARD)
        toolbar.pack(
            fill="x", padx=self.px(10), pady=self.px(8)
        )

        self.btn_scan = ttk.Button(
            toolbar, text="Сканировать (F5)", command=self._start_scan
        )
        self.btn_scan.pack(side="left")
        self.btn_backup = ttk.Button(
            toolbar, text="Резервная копия", command=self._on_backup
        )
        self.btn_backup.pack(side="left", padx=(self.px(6), 0))
        self.btn_restore = ttk.Button(
            toolbar,
            text="Восстановить из копии",
            style="Restore.TButton",
            command=self._on_restore,
        )
        self.btn_restore.pack(side="left", padx=(self.px(6), 0))
        self.btn_delete = ttk.Button(
            toolbar,
            text="Удалить выбранное",
            style="Danger.TButton",
            command=self._on_delete,
        )
        self.btn_delete.pack(side="left", padx=(self.px(6), 0))
        self.btn_cancel = ttk.Button(
            toolbar,
            text="Отменить",
            command=self._cancel,
            state="disabled",
        )
        self.btn_cancel.pack(side="left", padx=(self.px(6), 0))

        ttk.Button(
            toolbar, text="Открыть журнал", command=self._open_log
        ).pack(side="right")
        ttk.Button(
            toolbar,
            text="Папка резервных копий",
            command=lambda: self._open_backup_folder(None),
        ).pack(side="right", padx=(0, self.px(6)))
        self.check_revocation = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            toolbar,
            text="Проверять отзыв",
            variable=self.check_revocation,
        ).pack(side="right", padx=(0, self.px(10)))

    def _build_footer(self) -> None:
        footer = tk.Frame(
            self,
            bg=CARD,
            highlightbackground=SILVER,
            highlightthickness=1,
        )
        footer.pack(fill="x", side="bottom")
        inner = tk.Frame(footer, bg=CARD)
        inner.pack(fill="x", padx=self.px(14), pady=self.px(6))
        self.status_label = tk.Label(
            inner,
            text="Готово",
            font=self.font(11),
            bg=CARD,
            fg=MUTED,
            anchor="w",
        )
        self.status_label.pack(side="left")
        self.progress = ttk.Progressbar(
            inner,
            orient="horizontal",
            mode="determinate",
            length=self.px(250),
        )
        self.progress.pack(side="right", padx=(self.px(10), 0))
        link = tk.Label(
            inner,
            text="© %s, %s · github.com/AMarmeladov" % (AUTHOR, AUTHOR_YEAR),
            font=self.font(10),
            bg=CARD,
            fg=BLUE_DARK,
            cursor="hand2",
        )
        link.pack(side="right", padx=(0, self.px(16)))
        link.bind("<Button-1>", lambda _event: webbrowser.open(AUTHOR_URL))
        link.bind(
            "<Enter>",
            lambda _event: link.configure(fg=BLUE, font=self.font(10, "underline")),
        )
        link.bind(
            "<Leave>",
            lambda _event: link.configure(fg=BLUE_DARK, font=self.font(10)),
        )

    def _build_cert_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab, text="Сертификаты")

        top = tk.Frame(tab, bg=BG)
        top.pack(fill="x", padx=2, pady=(self.px(8), self.px(4)))
        tk.Label(top, text="Поиск:", bg=BG, fg=TEXT, font=self.font(12)).pack(
            side="left"
        )
        self.cert_search = tk.StringVar()
        ttk.Entry(top, textvariable=self.cert_search, width=32).pack(
            side="left", padx=(self.px(4), self.px(12))
        )
        tk.Label(top, text="Статус:", bg=BG, fg=TEXT, font=self.font(12)).pack(
            side="left"
        )
        self.cert_filter = tk.StringVar(value=CERT_FILTERS[0])
        combo = ttk.Combobox(
            top,
            textvariable=self.cert_filter,
            values=CERT_FILTERS,
            state="readonly",
            width=20,
        )
        combo.pack(side="left", padx=(self.px(4), self.px(12)))
        ttk.Button(
            top, text="Отметить просроченные", command=self._check_expired_certs
        ).pack(side="left")
        ttk.Button(top, text="Отметить всё", command=self._check_all_certs).pack(
            side="left", padx=(self.px(6), 0)
        )
        ttk.Button(top, text="Снять отметки", command=self._uncheck_certs).pack(
            side="left", padx=(self.px(6), 0)
        )

        self.cert_search.trace_add("write", lambda *_a: self._refresh_certs())
        combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_certs())

        pane = ttk.Panedwindow(tab, orient="vertical")
        pane.pack(fill="both", expand=True, padx=2, pady=(0, self.px(4)))
        tree_frame = tk.Frame(pane, bg=BG)
        pane.add(tree_frame, weight=3)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        columns = (
            "sel",
            "status",
            "revocation",
            "name",
            "subject",
            "expires",
            "stores",
            "containers",
            "thumb",
        )
        tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "sel": ("✓", 36),
            "status": ("Статус", 215),
            "revocation": ("Отзыв", 150),
            "name": ("Имя / CN", 230),
            "subject": ("Субъект", 300),
            "expires": ("Действителен до", 135),
            "stores": ("Хранилища", 230),
            "containers": ("Контейнеры", 170),
            "thumb": ("Отпечаток SHA1", 300),
        }
        for key, (heading, width) in headings.items():
            tree.heading(key, text=heading)
            tree.column(
                key,
                width=self.px(width),
                anchor="center" if key in ("sel", "expires") else "w",
                stretch=key in ("name", "subject", "stores", "thumb"),
            )
        tree.tag_configure("expired", foreground=DANGER)
        tree.tag_configure("revoked", foreground=DANGER)
        tree.tag_configure("valid", foreground=SUCCESS)
        tree.tag_configure("unknown", foreground=WARNING)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.cert_tree = tree

        tree.bind("<Button-1>", lambda e: self._on_tree_click(e, tree, "cert"))
        tree.bind("<Double-1>", lambda e: self._on_tree_double(e, tree, "cert"))
        tree.bind("<space>", lambda e: self._toggle_selected(tree, "cert"))
        tree.bind("<Control-a>", lambda e: self._check_all_certs())
        tree.bind("<<TreeviewSelect>>", lambda e: self._show_cert_details())
        self._add_context_menu(tree, "cert")

        details_frame = tk.Frame(pane, bg=BG)
        pane.add(details_frame, weight=1)
        details_frame.rowconfigure(1, weight=1)
        details_frame.columnconfigure(0, weight=1)
        tk.Label(
            details_frame,
            text="Подробности сертификата",
            font=self.font(11, "bold"),
            bg=BG,
            fg=NAVY_2,
        ).grid(row=0, column=0, sticky="w", pady=(self.px(4), self.px(2)))
        self.cert_details = tk.Text(
            details_frame,
            height=8,
            wrap="word",
            font=self.font(11, family="Consolas"),
            bg=CARD,
            fg=TEXT,
            relief="flat",
            highlightbackground=SILVER,
            highlightthickness=1,
            padx=self.px(8),
            pady=self.px(6),
            state="disabled",
        )
        self.cert_details.grid(row=1, column=0, sticky="nsew")
        dsb = ttk.Scrollbar(
            details_frame, orient="vertical", command=self.cert_details.yview
        )
        self.cert_details.configure(yscrollcommand=dsb.set)
        dsb.grid(row=1, column=1, sticky="ns")

    def _build_cont_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab, text="Контейнеры")

        top = tk.Frame(tab, bg=BG)
        top.pack(fill="x", padx=2, pady=(self.px(8), self.px(4)))
        tk.Label(top, text="Поиск:", bg=BG, fg=TEXT, font=self.font(12)).pack(
            side="left"
        )
        self.cont_search = tk.StringVar()
        ttk.Entry(top, textvariable=self.cont_search, width=28).pack(
            side="left", padx=(self.px(4), self.px(10))
        )
        tk.Label(top, text="Тип:", bg=BG, fg=TEXT, font=self.font(12)).pack(
            side="left"
        )
        self.cont_type = tk.StringVar(value=CONT_TYPES[0])
        type_combo = ttk.Combobox(
            top,
            textvariable=self.cont_type,
            values=CONT_TYPES,
            state="readonly",
            width=18,
        )
        type_combo.pack(side="left", padx=(self.px(4), self.px(10)))
        tk.Label(top, text="Статус:", bg=BG, fg=TEXT, font=self.font(12)).pack(
            side="left"
        )
        self.cont_filter = tk.StringVar(value=CONT_FILTERS[0])
        combo = ttk.Combobox(
            top,
            textvariable=self.cont_filter,
            values=CONT_FILTERS,
            state="readonly",
            width=18,
        )
        combo.pack(side="left", padx=(self.px(4), self.px(10)))
        ttk.Button(
            top, text="Отметить проблемные", command=self._check_problem_conts
        ).pack(side="left")
        ttk.Button(top, text="Отметить всё", command=self._check_all_conts).pack(
            side="left", padx=(self.px(6), 0)
        )
        ttk.Button(top, text="Снять отметки", command=self._uncheck_conts).pack(
            side="left", padx=(self.px(6), 0)
        )

        self.cont_search.trace_add("write", lambda *_a: self._refresh_conts())
        type_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_conts())
        combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_conts())

        pane = ttk.Panedwindow(tab, orient="vertical")
        pane.pack(fill="both", expand=True, padx=2, pady=(0, self.px(4)))
        tree_frame = tk.Frame(pane, bg=BG)
        pane.add(tree_frame, weight=3)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        columns = (
            "sel",
            "status",
            "kind",
            "media",
            "name",
            "location",
            "cert",
            "expires",
            "thumb",
        )
        tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="extended"
        )
        headings = {
            "sel": ("✓", 36),
            "status": ("Статус", 250),
            "kind": ("Тип", 80),
            "media": ("Носитель", 95),
            "name": ("Имя контейнера", 200),
            "location": ("Расположение", 340),
            "cert": ("Сертификат (имя / CN)", 240),
            "expires": ("Действителен до", 135),
            "thumb": ("Отпечаток SHA1", 300),
        }
        for key, (heading, width) in headings.items():
            tree.heading(key, text=heading)
            tree.column(
                key,
                width=self.px(width),
                anchor="center" if key in ("sel", "expires") else "w",
                stretch=key in ("name", "location", "cert", "thumb"),
            )
        tree.tag_configure("orphan", foreground=ORPHAN)
        tree.tag_configure("expired", foreground=DANGER)
        tree.tag_configure("valid", foreground=SUCCESS)
        tree.tag_configure("unknown", foreground=WARNING)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.cont_tree = tree

        tree.bind("<Button-1>", lambda e: self._on_tree_click(e, tree, "cont"))
        tree.bind("<Double-1>", lambda e: self._on_tree_double(e, tree, "cont"))
        tree.bind("<space>", lambda e: self._toggle_selected(tree, "cont"))
        tree.bind("<Control-a>", lambda e: self._check_all_conts())
        tree.bind("<<TreeviewSelect>>", lambda e: self._show_cont_details())
        self._add_context_menu(tree, "cont")

        details_frame = tk.Frame(pane, bg=BG)
        pane.add(details_frame, weight=1)
        details_frame.rowconfigure(1, weight=1)
        details_frame.columnconfigure(0, weight=1)
        tk.Label(
            details_frame,
            text="Подробности контейнера",
            font=self.font(11, "bold"),
            bg=BG,
            fg=NAVY_2,
        ).grid(row=0, column=0, sticky="w", pady=(self.px(4), self.px(2)))
        self.cont_details = tk.Text(
            details_frame,
            height=8,
            wrap="word",
            font=self.font(11, family="Consolas"),
            bg=CARD,
            fg=TEXT,
            relief="flat",
            highlightbackground=SILVER,
            highlightthickness=1,
            padx=self.px(8),
            pady=self.px(6),
            state="disabled",
        )
        self.cont_details.grid(row=1, column=0, sticky="nsew")
        dsb = ttk.Scrollbar(
            details_frame, orient="vertical", command=self.cont_details.yview
        )
        self.cont_details.configure(yscrollcommand=dsb.set)
        dsb.grid(row=1, column=1, sticky="ns")

    def _build_log_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(tab, text="Журнал")
        top = tk.Frame(tab, bg=BG)
        top.pack(fill="x", padx=2, pady=(self.px(8), self.px(4)))
        tk.Label(
            top,
            text="Журнал работы (INFO / OK / WARN / ERROR)",
            bg=BG,
            fg=MUTED,
            font=self.font(11),
        ).pack(side="left")
        ttk.Button(top, text="Открыть файл журнала", command=self._open_log).pack(
            side="right"
        )
        ttk.Button(top, text="Очистить окно", command=self._clear_log).pack(
            side="right", padx=(0, self.px(6))
        )
        frame = tk.Frame(tab, bg=BG)
        frame.pack(fill="both", expand=True, padx=2, pady=(0, self.px(4)))
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.log_text = tk.Text(
            frame,
            wrap="none",
            font=self.font(11, family="Consolas"),
            bg=LOG_BG,
            fg=LOG_FG,
            insertbackground=LOG_FG,
            relief="flat",
            padx=self.px(8),
            pady=self.px(6),
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.log_text.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.log_text.tag_configure("DEBUG", foreground="#8B9BB4")
        self.log_text.tag_configure("INFO", foreground=LOG_FG)
        self.log_text.tag_configure("OK", foreground="#7EE787")
        self.log_text.tag_configure("WARN", foreground="#FFD166")
        self.log_text.tag_configure("ERROR", foreground="#FF7B72")

    # ------------------------------------------------------------------
    # Журнал и очередь
    # ------------------------------------------------------------------
    def _on_log(self, level: str, line: str) -> None:
        self.queue.put(("log", level, line))

    def _append_log(self, level: str, line: str) -> None:
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line + "\n", level)
            lines = int(self.log_text.index("end-1c").split(".")[0])
            if lines > 6000:
                self.log_text.delete("1.0", "%d.0" % (lines - 5000))
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except Exception:
            pass

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _poll_queue(self) -> None:
        try:
            while True:
                try:
                    message = self.queue.get_nowait()
                except queue.Empty:
                    break
                self._handle_message(message)
        finally:
            self.after(120, self._poll_queue)

    def _handle_message(self, message: tuple) -> None:
        kind = message[0]
        if kind == "log":
            self._append_log(message[1], message[2])
        elif kind == "progress":
            self._set_progress(message[1], message[2], message[3])
        elif kind == "scan_done":
            self._on_scan_done(message[1])
        elif kind == "scan_error":
            self._set_busy(False)
            self.logger.error("Сканирование: %s" % message[1])
            messagebox.showerror("Ошибка сканирования", message[1], parent=self)
        elif kind == "scan_cancelled":
            self._set_busy(False)
            self.logger.warn("Сканирование отменено пользователем")
        elif kind == "backup_done":
            self._on_backup_created(message[1])
        elif kind == "backup_created":
            self._on_backup_created(message[1])
        elif kind == "backup_only_done":
            self._set_busy(False)
            self._on_backup_done(message[1])
        elif kind == "backup_incomplete":
            self._set_busy(False)
            self._on_backup_incomplete(message[1])
        elif kind == "restore_done":
            self._on_restore_done(message[1], message[2])
        elif kind == "restore_cancelled":
            self._set_busy(False)
            self.logger.warn("Восстановление отменено пользователем")
        elif kind == "restore_error":
            self._set_busy(False)
            self.logger.error("Восстановление: %s" % message[1])
            messagebox.showerror("Ошибка восстановления", message[1], parent=self)
        elif kind == "delete_done":
            self._on_delete_done(message[1], message[2])
        elif kind == "delete_cancelled":
            self._set_busy(False)
            self.logger.warn("Удаление отменено пользователем")
        elif kind == "work_error":
            self._set_busy(False)
            self.logger.error("Операция: %s" % message[1])
            messagebox.showerror("Ошибка", message[1], parent=self)

    def _set_progress(self, text: str, current: int, total: int) -> None:
        try:
            self.status_label.configure(text=text)
            if total > 0:
                if str(self.progress.cget("mode")) != "determinate":
                    self.progress.stop()
                    self.progress.configure(mode="determinate")
                self.progress.configure(maximum=total, value=current)
            else:
                if str(self.progress.cget("mode")) != "indeterminate":
                    self.progress.configure(mode="indeterminate")
                    self.progress.start(12)
        except Exception:
            pass

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = "disabled" if busy else "normal"
        for button in (
            self.btn_scan,
            self.btn_backup,
            self.btn_restore,
            self.btn_delete,
        ):
            try:
                button.configure(state=state)
            except Exception:
                pass
        try:
            if winapi.is_admin():
                self.btn_elevate.configure(state="disabled")
            else:
                self.btn_elevate.configure(
                    state="disabled" if busy else "normal"
                )
        except Exception:
            pass
        try:
            self.btn_cancel.configure(state="normal" if busy else "disabled")
        except Exception:
            pass
        if not busy:
            try:
                self.progress.stop()
                self.progress.configure(mode="determinate", value=0)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Сканирование
    # ------------------------------------------------------------------
    def _start_scan(self) -> None:
        if self.busy:
            return
        self._set_busy(True)
        self.cancel_event = threading.Event()
        self._set_progress("Сканирование...", 0, 0)
        # Tk-переменные читаем в главном потоке: обращение к ним из
        # рабочего потока приводит к RuntimeError "main thread is not in main loop".
        check_revocation = bool(self.check_revocation.get())
        thread = threading.Thread(
            target=self._scan_worker,
            args=(check_revocation,),
            daemon=True,
        )
        thread.start()

    def _scan_worker(self, check_revocation: bool) -> None:
        try:
            tools = ToolRunner(self.logger, self.cancel_event)
            scanner = Scanner(
                self.logger,
                tools,
                cancel_event=self.cancel_event,
                progress=lambda text, current, total: self.queue.put(
                    ("progress", text, current, total)
                ),
                check_revocation=check_revocation,
            )
            result = scanner.scan_all()
            self.queue.put(("scan_done", result))
        except ScanCancelled:
            self.queue.put(("scan_cancelled",))
        except Exception as exc:
            self.queue.put(
                ("scan_error", "%s: %s" % (type(exc).__name__, exc))
            )

    def _on_scan_done(self, result: ScanResult) -> None:
        self.result = result
        self.certificates = result.certificates
        self.containers = result.containers
        self.checked_certs &= {c.thumbprint for c in self.certificates}
        self.checked_conts &= {c.key for c in self.containers}
        self._refresh_certs()
        self._refresh_conts()
        counts = result.counts
        self.summary_label.configure(
            text=(
                "Сертификатов: %d (просрочено: %d, отозвано: %d, с ключом: %d)    "
                "Контейнеров: %d (проблемных: %d, без данных: %d)    "
                "Время: %.1f с"
                % (
                    counts.get("cert_total", 0),
                    counts.get("cert_expired", 0),
                    counts.get("cert_revoked", 0),
                    counts.get("cert_with_key", 0),
                    counts.get("cont_total", 0),
                    counts.get("cont_expired", 0) + counts.get("cont_orphan", 0),
                    counts.get("cont_unknown", 0),
                    result.duration,
                )
            )
        )
        self._set_busy(False)
        self.status_label.configure(text="Сканирование завершено")
        if result.errors:
            self.logger.warn(
                "Во время сканирования возникло предупреждений: %d"
                % len(result.errors)
            )

    # ------------------------------------------------------------------
    # Таблицы
    # ------------------------------------------------------------------
    def _cert_matches(self, cert: Certificate) -> bool:
        text = self.cert_search.get().strip().lower()
        if text:
            haystack = " ".join(
                [
                    cert.display_name,
                    cert.subject,
                    cert.issuer,
                    cert.thumbprint,
                    cert.container_display,
                    cert.source_display,
                    cert.revocation_display,
                ]
            ).lower()
            if text not in haystack:
                return False
        mode = self.cert_filter.get()
        if mode == "Просроченные":
            return cert.is_expired
        if mode == "Действительные":
            return cert.date_known and not cert.is_expired
        if mode == "Дата неизвестна":
            return not cert.date_known
        if mode == "С закрытым ключом":
            return cert.has_private_key
        if mode == "Отозванные":
            return cert.revocation == "revoked"
        return True

    def _cont_matches(self, container: Container) -> bool:
        text = self.cont_search.get().strip().lower()
        if text:
            haystack = " ".join(
                [
                    container.name,
                    container.subject,
                    container.cert_display,
                    container.thumbprint,
                    container.path or "",
                    container.reg_path or "",
                    container.full_name or "",
                    container.source,
                    container.note,
                ]
            ).lower()
            if text not in haystack:
                return False
        type_mode = self.cont_type.get()
        if type_mode == "Реестр" and container.kind != "Registry":
            return False
        if type_mode == "Файловые (HDD)" and not (
            container.kind == "File" and container.media == "HDD"
        ):
            return False
        if type_mode == "USB/съёмные" and container.media != "USB":
            return False
        if type_mode == "Неизвестные" and container.kind != "Unknown":
            return False

        mode = self.cont_filter.get()
        if mode == "Проблемные":
            return container.is_problem
        if mode == "Просроченные":
            return container.is_expired
        if mode == "Осиротевшие":
            return container.orphan is True
        if mode == "Действительные":
            return (
                container.date_known
                and not container.is_expired
                and container.orphan is not True
                and container.info_known
            )
        if mode == "Дата неизвестна":
            return not container.date_known
        if mode == "Нет данных":
            return not container.info_known
        return True

    def _refresh_certs(self) -> None:
        tree = getattr(self, "cert_tree", None)
        if tree is None:
            return
        selected = set(tree.selection())
        tree.delete(*tree.get_children())
        self._cert_rows.clear()
        index = 0
        for cert in self.certificates:
            if not self._cert_matches(cert):
                continue
            iid = str(index)
            index += 1
            self._cert_rows[iid] = cert
            if cert.revocation == "revoked":
                tag = "revoked"
            elif cert.is_expired:
                tag = "expired"
            elif not cert.date_known:
                tag = "unknown"
            else:
                tag = "valid"
            tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "✓" if cert.thumbprint in self.checked_certs else "",
                    cert.status,
                    cert.revocation_short,
                    _truncate(cert.display_name, 100),
                    _truncate(cert.subject, 150),
                    format_dt(cert.not_after),
                    _truncate(cert.source_display, 120),
                    _truncate(cert.container_display, 100),
                    cert.thumbprint,
                ),
                tags=(tag,),
            )
        for iid in selected:
            if tree.exists(iid):
                tree.selection_add(iid)

    def _refresh_conts(self) -> None:
        tree = getattr(self, "cont_tree", None)
        if tree is None:
            return
        selected = set(tree.selection())
        tree.delete(*tree.get_children())
        self._cont_rows.clear()
        index = 0
        for container in self.containers:
            if not self._cont_matches(container):
                continue
            iid = str(index)
            index += 1
            self._cont_rows[iid] = container
            if container.orphan is True:
                tag = "orphan"
            elif container.is_expired:
                tag = "expired"
            elif not container.date_known or not container.info_known:
                tag = "unknown"
            else:
                tag = "valid"
            tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "✓" if container.key in self.checked_conts else "",
                    container.status,
                    container.kind_display,
                    container.media_display,
                    _truncate(container.name, 100),
                    _truncate(_container_location(container), 200),
                    _truncate(container.cert_display, 90),
                    format_dt(container.not_after),
                    container.thumbprint,
                ),
                tags=(tag,),
            )
        for iid in selected:
            if tree.exists(iid):
                tree.selection_add(iid)

    # ------------------------------------------------------------------
    # Отметки и подробности
    # ------------------------------------------------------------------
    def _on_tree_click(self, event, tree, kind: str) -> Optional[str]:
        if tree.identify("region", event.x, event.y) != "cell":
            return None
        if tree.identify_column(event.x) != "#1":
            return None
        iid = tree.identify_row(event.y)
        if iid:
            self._toggle_row(iid, kind)
        return "break"

    def _on_tree_double(self, event, tree, kind: str) -> Optional[str]:
        iid = tree.identify_row(event.y)
        if iid:
            self._toggle_row(iid, kind)
        return "break"

    def _toggle_selected(self, tree, kind: str) -> str:
        for iid in tree.selection():
            self._toggle_row(iid, kind)
        return "break"

    def _toggle_row(self, iid: str, kind: str) -> None:
        if kind == "cert":
            cert = self._cert_rows.get(iid)
            if not cert:
                return
            if cert.thumbprint in self.checked_certs:
                self.checked_certs.discard(cert.thumbprint)
                mark = ""
            else:
                self.checked_certs.add(cert.thumbprint)
                mark = "✓"
            self._set_row_mark(self.cert_tree, iid, mark)
        else:
            container = self._cont_rows.get(iid)
            if not container:
                return
            if container.key in self.checked_conts:
                self.checked_conts.discard(container.key)
                mark = ""
            else:
                self.checked_conts.add(container.key)
                mark = "✓"
            self._set_row_mark(self.cont_tree, iid, mark)

    def _set_row_mark(self, tree, iid: str, mark: str) -> None:
        try:
            values = list(tree.item(iid, "values"))
            values[0] = mark
            tree.item(iid, values=values)
        except Exception:
            pass

    def _check_expired_certs(self) -> None:
        for cert in self.certificates:
            if cert.is_expired and self._cert_matches(cert):
                self.checked_certs.add(cert.thumbprint)
        self._refresh_certs()

    def _check_all_certs(self) -> None:
        for cert in self.certificates:
            if self._cert_matches(cert):
                self.checked_certs.add(cert.thumbprint)
        self._refresh_certs()

    def _uncheck_certs(self) -> None:
        self.checked_certs.clear()
        self._refresh_certs()

    def _check_problem_conts(self) -> None:
        for container in self.containers:
            if container.is_problem and self._cont_matches(container):
                self.checked_conts.add(container.key)
        self._refresh_conts()

    def _check_all_conts(self) -> None:
        for container in self.containers:
            if self._cont_matches(container):
                self.checked_conts.add(container.key)
        self._refresh_conts()

    def _uncheck_conts(self) -> None:
        self.checked_conts.clear()
        self._refresh_conts()

    def _select_all_current(self, _event=None) -> str:
        try:
            current = self.notebook.index(self.notebook.select())
        except Exception:
            return "break"
        if current == 0:
            self._check_all_certs()
        elif current == 1:
            self._check_all_conts()
        return "break"

    def _add_context_menu(self, tree, kind: str) -> None:
        menu = tk.Menu(
            self,
            tearoff=0,
            bg=CARD,
            fg=TEXT,
            activebackground=BLUE,
            activeforeground="white",
            font=self.font(11),
        )
        menu.add_command(
            label="Отметить / снять",
            command=lambda: self._toggle_selected(tree, kind),
        )
        menu.add_command(
            label="Копировать отпечаток",
            command=lambda: self._copy_field(tree, kind, "thumb"),
        )
        menu.add_command(
            label="Копировать расположение",
            command=lambda: self._copy_field(tree, kind, "location"),
        )

        def show(event) -> None:
            iid = tree.identify_row(event.y)
            if iid and iid not in tree.selection():
                tree.selection_set(iid)
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        tree.bind("<Button-3>", show)

    def _copy_field(self, tree, kind: str, field: str) -> None:
        selection = tree.selection()
        if not selection:
            return
        iid = selection[0]
        if kind == "cert":
            cert = self._cert_rows.get(iid)
            if not cert:
                return
            value = cert.thumbprint if field == "thumb" else cert.source_display
        else:
            container = self._cont_rows.get(iid)
            if not container:
                return
            value = (
                container.thumbprint
                if field == "thumb"
                else _container_location(container)
            )
        if value:
            self.clipboard_clear()
            self.clipboard_append(value)
            self.status_label.configure(text="Скопировано в буфер обмена")

    def _show_cert_details(self) -> None:
        selection = self.cert_tree.selection()
        if not selection:
            return
        cert = self._cert_rows.get(selection[0])
        if not cert:
            return
        lines = [
            "Сертификат",
            "==========",
            "Имя / CN: %s" % cert.display_name,
            "Отпечаток SHA1: %s" % cert.thumbprint,
            "Субъект: %s" % cert.subject,
            "Издатель: %s" % cert.issuer,
            "Серийный номер: %s" % (cert.serial or "—"),
            "Действителен с: %s" % format_dt(cert.not_before),
            "Действителен до: %s" % format_dt(cert.not_after),
            "Статус: %s" % cert.status,
            "Отзыв: %s" % cert.revocation_display,
            "Закрытый ключ: %s" % ("есть" if cert.has_private_key else "нет"),
            "Расположение: %s" % cert.source_display,
            "",
            "Хранилища:",
        ]
        for location in cert.locations:
            lines.append(
                "  - %s (%s)%s"
                % (
                    location.display,
                    location.code,
                    " [ключ]" if location.has_private_key else "",
                )
            )
        if cert.containers:
            lines.append("")
            lines.append("Связанные контейнеры:")
            for container in cert.containers:
                lines.append("  - %s" % container.name)
                lines.append("    %s" % _container_location(container))
                if container.note:
                    lines.append("    %s" % container.note)
        if cert.crl_urls or cert.ocsp_urls:
            lines.append("")
            lines.append("Точки проверки отзыва:")
            for url in cert.crl_urls:
                lines.append("  CRL:  %s" % url)
            for url in cert.ocsp_urls:
                lines.append("  OCSP: %s" % url)
        if cert.note:
            lines.append("")
            lines.append("Примечание: %s" % cert.note)
        self._set_text(self.cert_details, "\n".join(lines))

    def _show_cont_details(self) -> None:
        selection = self.cont_tree.selection()
        if not selection:
            return
        container = self._cont_rows.get(selection[0])
        if not container:
            return
        lines = [
            "Контейнер закрытого ключа",
            "=========================",
            "Имя: %s" % container.name,
            "Имя в контейнере: %s" % (container.internal_name or "—"),
            "Тип: %s" % container.kind_display,
            "Носитель: %s" % container.media_display,
            "Статус: %s" % container.status,
            "Отзыв: %s" % container.revocation_display,
            "Расположение: %s" % _container_location(container),
            "Путь: %s" % (container.path or "—"),
            "Реестр: %s" % (container.reg_path or "—"),
            "Полное имя CSP: %s" % (container.full_name or "—"),
            "Источник: %s" % (container.source or "—"),
            "",
            "Отпечаток сертификата: %s" % (container.thumbprint or "—"),
            "Субъект: %s" % (container.subject or "—"),
            "Действителен до: %s" % format_dt(container.not_after),
            "Сертификат в Windows: %s" % container.cert_display,
        ]
        if container.note:
            lines.append("Примечание: %s" % container.note)
        self._set_text(self.cont_details, "\n".join(lines))

    def _set_text(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # ------------------------------------------------------------------
    # Выбранные объекты
    # ------------------------------------------------------------------
    def _checked_certificates(self) -> List[Certificate]:
        return [
            cert
            for cert in self.certificates
            if cert.thumbprint in self.checked_certs
        ]

    def _checked_containers(self) -> List[Container]:
        return [
            container
            for container in self.containers
            if container.key in self.checked_conts
        ]

    # ------------------------------------------------------------------
    # Резервное копирование
    # ------------------------------------------------------------------
    def _on_backup(self) -> None:
        if self.busy:
            return
        certs = self._checked_certificates()
        containers = self._checked_containers()
        if not certs and not containers:
            messagebox.showinfo(
                "Резервная копия",
                "Отметьте сертификаты и/или контейнеры, которые нужно сохранить.",
                parent=self,
            )
            return
        self._start_backup_worker(certs, containers)

    def _start_backup_worker(
        self, certs: List[Certificate], containers: List[Container]
    ) -> None:
        self._set_busy(True)
        self.cancel_event = threading.Event()
        self._set_progress("Создание резервной копии...", 0, 0)
        thread = threading.Thread(
            target=self._backup_worker,
            args=(certs, containers),
            daemon=True,
        )
        thread.start()

    def _backup_worker(
        self, certs: List[Certificate], containers: List[Container]
    ) -> None:
        try:
            tools = ToolRunner(self.logger, self.cancel_event)
            manager = BackupManager(
                self.logger,
                tools,
                base_dir=self.base_dir,
                cancel_event=self.cancel_event,
                progress=lambda text, current, total: self.queue.put(
                    ("progress", text, current, total)
                ),
            )
            summary = manager.create_backup(
                certs,
                collect_backup_containers(certs, containers),
                log_path=self.logger.path,
            )
            self.queue.put(("backup_only_done", summary))
        except BackupCancelled:
            self.queue.put(("delete_cancelled",))
        except Exception as exc:
            self.queue.put(
                ("work_error", "%s: %s" % (type(exc).__name__, exc))
            )

    def _log_backup_summary(self, summary: BackupSummary) -> None:
        text = (
            "Резервная копия: %s (сертификатов %d, контейнеров %d, файлов %d, "
            "ключей в PFX %d, не экспортировано %d, ошибок %d)"
            % (
                summary.path,
                summary.certs,
                summary.containers,
                summary.files,
                summary.keys_exported,
                summary.keys_missing,
                summary.failures,
            )
        )
        if summary.failures:
            self.logger.error(text)
        else:
            self.logger.ok(text)

    def _on_backup_created(self, summary: BackupSummary) -> None:
        """Тихий отчёт: резервная копия создана в ходе удаления."""
        self._last_backup = summary
        self.status_label.configure(
            text="Резервная копия создана, продолжается удаление..."
        )
        self._log_backup_summary(summary)

    def _on_backup_done(self, summary: BackupSummary) -> None:
        self._last_backup = summary
        self.status_label.configure(text="Резервная копия создана")
        self._log_backup_summary(summary)
        lines = [
            "Резервная копия создана в одном файле.",
            "",
            "Файл: %s" % summary.path,
            "Размер: %s" % _format_size(summary.path),
            "Сертификатов: %d" % summary.certs,
            "Контейнеров: %d" % summary.containers,
            "Файлов внутри архива: %d" % summary.files,
            "Ошибок: %d" % summary.failures,
            "Закрытых ключей в PFX: %d" % summary.keys_exported,
            "Ключей не экспортировано: %d" % summary.keys_missing,
            "Проверка восстановимости: %s"
            % ("пройдена" if summary.verified else "НЕ пройдена"),
            "",
            "Пароль для PFX-файлов сохранён в PASSWORD.txt внутри архива.",
            "README.txt содержит инструкцию по восстановлению.",
        ]
        if summary.keys_missing:
            lines.append("")
            lines.append(
                "ВНИМАНИЕ: %d закрытых ключей неэкспортируемы и не попали в PFX. "
                "Восстановление таких ключей возможно только из копий "
                "контейнеров (containers/ и registry/)." % summary.keys_missing
            )
        if summary.failures:
            lines.append("")
            lines.append(
                "ВНИМАНИЕ: часть объектов сохранить не удалось. Проверьте журнал."
            )
        if summary.unrestorable:
            lines.append("")
            lines.append(
                "ВНИМАНИЕ: для %d объектов восстановление не гарантируется:"
                % len(summary.unrestorable)
            )
            for text in summary.unrestorable[:15]:
                lines.append("  - " + text)
            if len(summary.unrestorable) > 15:
                lines.append(
                    "  ... и ещё %d" % (len(summary.unrestorable) - 15)
                )
        messagebox.showinfo("Резервная копия", "\n".join(lines), parent=self)

    def _on_backup_incomplete(self, summary: BackupSummary) -> None:
        self._last_backup = summary
        problems = list(summary.unrestorable)
        self.logger.error(
            "Резервная копия не подтверждена (ошибок %d, невосстановимых %d). "
            "Удаление отменено."
            % (summary.failures, len(problems))
        )
        lines = [
            "Резервная копия не прошла проверку — удаление отменено, "
            "чтобы не потерять данные.",
            "",
            "Файл: %s" % summary.path,
            "Ошибок при создании: %d" % summary.failures,
            "Объектов без гарантии восстановления: %d" % len(problems),
        ]
        if problems:
            lines.append("")
            lines.append("Нельзя гарантировать восстановление:")
            for text in problems[:15]:
                lines.append("  - " + text)
            if len(problems) > 15:
                lines.append("  ... и ещё %d" % (len(problems) - 15))
        if summary.verification_messages:
            lines.append("")
            lines.append("Проверка копии:")
            for text in summary.verification_messages[:10]:
                lines.append("  - " + text)
        lines.append("")
        lines.append(
            "Проверьте журнал. Можно повторить попытку или выбрать удаление "
            "без резервной копии (с подтверждением и на свой риск)."
        )
        messagebox.showwarning(
            "Резервная копия не подтверждена",
            "\n".join(lines),
            parent=self,
        )

    # ------------------------------------------------------------------
    # Восстановление
    # ------------------------------------------------------------------
    def _on_restore(self) -> None:
        if self.busy:
            return
        initial = choose_backup_root(self.base_dir)
        path = filedialog.askopenfilename(
            title="Выберите резервную копию CryptoCleaner",
            initialdir=initial,
            filetypes=[
                ("Резервная копия CryptoCleaner", "*" + BACKUP_EXTENSION),
                ("Архивы ZIP", "*.zip"),
                ("Все файлы", "*.*"),
            ],
            parent=self,
        )
        if not path:
            return
        try:
            contents = BackupReader.load(path)
        except Exception as exc:
            self.logger.error("Не удалось открыть резервную копию: %s" % exc)
            messagebox.showerror("Восстановление", str(exc), parent=self)
            return
        if not contents.certificates and not contents.containers:
            messagebox.showinfo(
                "Восстановление",
                "В резервной копии нет сертификатов и контейнеров.",
                parent=self,
            )
            return
        self.logger.info(
            "Открыта резервная копия: %s (сертификатов %d, контейнеров %d)"
            % (contents.path, len(contents.certificates), len(contents.containers))
        )
        dialog = RestoreDialog(self, contents, self._start_restore_worker)
        dialog.focus_set()

    def _start_restore_worker(
        self,
        contents: BackupContents,
        thumbs: List[str],
        keys: List[str],
        overwrite: bool,
    ) -> None:
        self._set_busy(True)
        self.cancel_event = threading.Event()
        self._set_progress("Восстановление из резервной копии...", 0, 0)
        thread = threading.Thread(
            target=self._restore_worker,
            args=(contents, thumbs, keys, overwrite),
            daemon=True,
        )
        thread.start()

    def _restore_worker(
        self,
        contents: BackupContents,
        thumbs: List[str],
        keys: List[str],
        overwrite: bool,
    ) -> None:
        try:
            tools = ToolRunner(self.logger, self.cancel_event)
            manager = RestoreManager(
                self.logger,
                tools,
                cancel_event=self.cancel_event,
                progress=lambda text, current, total: self.queue.put(
                    ("progress", text, current, total)
                ),
            )
            results = manager.restore(contents, thumbs, keys, overwrite)
            self.queue.put(("restore_done", results, contents))
        except RestoreCancelled:
            self.queue.put(("restore_cancelled",))
        except Exception as exc:
            self.queue.put(
                ("restore_error", "%s: %s" % (type(exc).__name__, exc))
            )

    def _on_restore_done(
        self, results: List[OperationResult], contents: BackupContents
    ) -> None:
        self._set_busy(False)
        success = sum(1 for result in results if result.success)
        failed = len(results) - success
        self.logger.info(
            "Восстановление завершено. Успешно: %d, ошибок: %d." % (success, failed)
        )
        self.status_label.configure(
            text="Восстановление завершено: успешно %d, ошибок %d"
            % (success, failed)
        )
        window = ResultsWindow(
            self,
            results,
            title="Результат восстановления",
            subtitle="Источник: %s" % contents.path,
            open_path=contents.path,
        )
        window.focus_set()
        self.after(600, self._start_scan)

    # ------------------------------------------------------------------
    # Удаление
    # ------------------------------------------------------------------
    def _ask_danger_confirmation(
        self, title: str, message: str, word: str
    ) -> bool:
        """Запросить ввод контрольного слова для опасного действия."""
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.transient(self)
        dialog.resizable(False, False)
        dialog.configure(bg=BG)
        result = {"ok": False}

        frame = tk.Frame(dialog, bg=BG, padx=self.px(22), pady=self.px(18))
        frame.pack(fill="both", expand=True)
        tk.Label(
            frame,
            text=message,
            bg=BG,
            fg=TEXT,
            justify="left",
            font=self.font(12),
            wraplength=self.px(640),
        ).pack(anchor="w")
        tk.Label(
            frame,
            text="Для подтверждения введите слово %s:" % word,
            bg=BG,
            fg=DANGER,
            justify="left",
            font=self.font(12, weight="bold"),
        ).pack(anchor="w", pady=(self.px(14), self.px(6)))
        var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=var, font=self.font(13))
        entry.pack(fill="x")
        error = tk.Label(
            frame, text="", bg=BG, fg=DANGER, font=self.font(11)
        )
        error.pack(anchor="w", pady=(self.px(4), 0))

        buttons = tk.Frame(frame, bg=BG)
        buttons.pack(fill="x", pady=(self.px(16), 0))

        def confirm(event=None) -> None:
            if var.get().strip() != word:
                error.configure(text="Слово введено неверно.")
                entry.focus_set()
                return
            result["ok"] = True
            dialog.destroy()

        def cancel(event=None) -> None:
            dialog.destroy()

        ttk.Button(
            buttons, text="Удалить без копии", command=confirm
        ).pack(side="right")
        ttk.Button(buttons, text="Отмена", command=cancel).pack(
            side="right", padx=(0, self.px(8))
        )
        dialog.bind("<Return>", confirm)
        dialog.bind("<Escape>", cancel)
        dialog.protocol("WM_DELETE_WINDOW", cancel)
        self.place_dialog(dialog, self.px(700), self.px(330))
        dialog.grab_set()
        entry.focus_set()
        self.wait_window(dialog)
        return bool(result["ok"])

    def _on_delete(self) -> None:
        if self.busy:
            return
        certs = self._checked_certificates()
        containers = self._checked_containers()
        if not certs and not containers:
            messagebox.showinfo(
                "Удаление",
                "Ничего не отмечено. Поставьте галочки в таблицах "
                "сертификатов и контейнеров.",
                parent=self,
            )
            return

        warnings: List[str] = []
        valid_containers = [
            c
            for c in containers
            if c.cert_found and c.date_known and not c.is_expired
        ]
        if valid_containers:
            warnings.append(
                "Среди контейнеров есть связанные с ДЕЙСТВУЮЩИМИ "
                "сертификатами: %d. После удаления закрытый ключ будет "
                "потерян." % len(valid_containers)
            )
        key_certs = [c for c in certs if c.has_private_key]
        if key_certs:
            warnings.append(
                "У %d сертификатов есть закрытый ключ. Если их контейнеры "
                "не отмечены, ключи останутся на диске." % len(key_certs)
            )
        revoked_certs = [c for c in certs if c.revocation == "revoked"]
        if revoked_certs:
            warnings.append(
                "Среди выбранных сертификатов есть ОТОЗВАННЫЕ: %d. "
                "Их удаление обычно безопасно, но проверьте причину отзыва."
                % len(revoked_certs)
            )
        revoked_conts = [c for c in containers if c.revocation == "revoked"]
        if revoked_conts:
            warnings.append(
                "Среди выбранных контейнеров есть связанные с ОТОЗВАННЫМИ "
                "сертификатами: %d." % len(revoked_conts)
            )
        unknown_rev = sum(1 for c in certs if c.revocation == "unknown")
        if unknown_rev:
            warnings.append(
                "Статус отзыва неизвестен у %d сертификатов: CRL/OCSP "
                "недоступны. Это не значит, что они действительны."
                % unknown_rev
            )
        if not winapi.is_admin():
            machine_certs = sum(
                1
                for cert in certs
                for loc in cert.locations
                if loc.location == "LocalMachine"
            )
            machine_conts = sum(
                1
                for container in containers
                if container.reg_hive == "HKLM"
            )
            if machine_certs or machine_conts:
                warnings.append(
                    "Есть объекты в хранилище компьютера (%d сертификатов, "
                    "%d контейнеров HKLM). Без прав администратора их "
                    "удаление, скорее всего, не удастся."
                    % (machine_certs, machine_conts)
                )

        offer = messagebox.askyesnocancel(
            "Резервная копия",
            "Перед удалением рекомендуется создать резервную копию.\n\n"
            "Да — создать копию и затем удалить\n"
            "Нет — удалить без резервной копии\n"
            "Отмена — ничего не делать",
            parent=self,
        )
        if offer is None:
            return
        do_backup = bool(offer)
        if not do_backup:
            if not self._ask_danger_confirmation(
                "Удаление без резервной копии",
                "Вы выбрали удаление БЕЗ резервной копии.\n\n"
                "Восстановить удалённые сертификаты и закрытые ключи будет "
                "невозможно: копии не существует.",
                "УДАЛИТЬ",
            ):
                return

        text = [
            "Будет удалено:",
            "  сертификатов: %d" % len(certs),
            "  контейнеров: %d" % len(containers),
            "",
            "Резервная копия: %s" % ("да" if do_backup else "НЕТ"),
        ]
        if warnings:
            text.append("")
            text.append("Внимание:")
            text.extend("  - " + item for item in warnings)
        text.append("")
        text.append("Продолжить удаление?")
        if not messagebox.askyesno(
            "Подтверждение удаления",
            "\n".join(text),
            icon="warning",
            parent=self,
        ):
            return

        self._start_delete_worker(certs, containers, do_backup)

    def _start_delete_worker(
        self,
        certs: List[Certificate],
        containers: List[Container],
        do_backup: bool,
    ) -> None:
        self._set_busy(True)
        self.cancel_event = threading.Event()
        self._set_progress("Подготовка к удалению...", 0, 0)
        thread = threading.Thread(
            target=self._delete_worker,
            args=(certs, containers, do_backup),
            daemon=True,
        )
        thread.start()

    def _delete_worker(
        self,
        certs: List[Certificate],
        containers: List[Container],
        do_backup: bool,
    ) -> None:
        try:
            tools = ToolRunner(self.logger, self.cancel_event)
            progress = lambda text, current, total: self.queue.put(
                ("progress", text, current, total)
            )
            summary: Optional[BackupSummary] = None
            if do_backup:
                manager = BackupManager(
                    self.logger,
                    tools,
                    base_dir=self.base_dir,
                    cancel_event=self.cancel_event,
                    progress=progress,
                )
                summary = manager.create_backup(
                    certs,
                    collect_backup_containers(certs, containers),
                    log_path=self.logger.path,
                )
                self.queue.put(("backup_created", summary))
                if summary.failures or summary.unrestorable:
                    self.queue.put(("backup_incomplete", summary))
                    return
            deleter = Deleter(
                self.logger,
                tools,
                cancel_event=self.cancel_event,
                progress=progress,
            )
            results = deleter.delete_all(certs, containers)
            self.queue.put(("delete_done", results, summary))
        except (BackupCancelled, DeleteCancelled):
            self.queue.put(("delete_cancelled",))
        except Exception as exc:
            self.queue.put(
                ("work_error", "%s: %s" % (type(exc).__name__, exc))
            )

    def _on_delete_done(
        self, results: List[OperationResult], backup: Optional[BackupSummary]
    ) -> None:
        self._set_busy(False)
        success = sum(1 for r in results if r.success)
        failed = len(results) - success
        for result in results:
            if result.success and result.target_key:
                if result.kind == "Сертификат":
                    self.checked_certs.discard(result.target_key.replace("CERT:", ""))
                else:
                    self.checked_conts.discard(result.target_key)
        self.logger.info(
            "Удаление завершено. Успешно: %d, ошибок: %d." % (success, failed)
        )
        self.status_label.configure(
            text="Удаление завершено: успешно %d, ошибок %d" % (success, failed)
        )
        self._refresh_certs()
        self._refresh_conts()
        window = ResultsWindow(
            self,
            results,
            title="Результат удаления",
            backup=backup,
        )
        window.focus_set()
        self.after(400, self._start_scan)

    # ------------------------------------------------------------------
    # Прочее
    # ------------------------------------------------------------------
    def _cancel(self) -> None:
        if self.busy:
            self.cancel_event.set()
            self.status_label.configure(
                text="Отмена... дождитесь завершения текущей операции"
            )
            self.logger.warn("Пользователь запросил отмену операции")

    def _open_log(self) -> None:
        path = self.logger.path
        if path and os.path.isfile(path):
            try:
                os.startfile(path)
                return
            except Exception:
                pass
        messagebox.showinfo(
            "Журнал",
            "Файл журнала: %s" % (path or "не создан"),
            parent=self,
        )

    def _open_path(self, path: str) -> None:
        if not path:
            return
        try:
            if os.path.isfile(path):
                os.startfile(os.path.dirname(os.path.abspath(path)))
            elif os.path.isdir(path):
                os.startfile(path)
            else:
                os.makedirs(path, exist_ok=True)
                os.startfile(path)
        except Exception as exc:
            messagebox.showerror("Открыть папку", str(exc), parent=self)

    def _open_backup_folder(self, summary: Optional[BackupSummary]) -> None:
        path = ""
        if summary is not None and summary.path:
            path = summary.path
        elif self._last_backup is not None:
            path = self._last_backup.path
        if not path:
            path = choose_backup_root(self.base_dir)
        self._open_path(path)

    def _elevate(self) -> None:
        if winapi.is_admin():
            messagebox.showinfo(
                "Права администратора",
                "Программа уже запущена с правами администратора.",
                parent=self,
            )
            return
        if getattr(sys, "frozen", False):
            executable = sys.executable
            params = subprocess.list2cmdline(sys.argv[1:])
        else:
            executable = sys.executable
            params = subprocess.list2cmdline(
                [os.path.abspath(sys.argv[0])] + sys.argv[1:]
            )
        try:
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", executable, params, self.base_dir, 1
            )
            if result <= 32:
                raise OSError("ShellExecuteW вернул %d" % result)
        except Exception as exc:
            messagebox.showerror(
                "Не удалось повысить права",
                "Запуск от имени администратора не удался: %s" % exc,
                parent=self,
            )
            return
        self._on_close()

    def _on_close(self) -> None:
        if self.busy:
            if not messagebox.askyesno(
                "Выход",
                "Выполняется операция. Прервать её и закрыть программу?",
                parent=self,
            ):
                return
            self.cancel_event.set()
        try:
            self.logger.info("Программа закрыта пользователем.")
            self.logger.close()
        except Exception:
            pass
        self.destroy()


def run_gui(base_dir: str = "", log_path: str = "") -> int:
    winapi.set_dpi_awareness()
    winapi.set_app_user_model_id()
    app = CryptoCleanerApp(base_dir=base_dir, log_path=log_path)
    app.mainloop()
    return 0
