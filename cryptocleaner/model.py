"""Модели данных CertCleaner."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


def normalize_thumb(value: Optional[str]) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()


# Признаки издателей, которые важно выделять отдельно: сертификаты,
# выпущенные УЦ Минцифры (включая прежнее название Минкомсвязь и НУЦ России)
# и УЦ Федерального казначейства.
ISSUER_GROUP_MINTSIFRY = "mintsifry"
ISSUER_GROUP_TREASURY = "treasury"
ISSUER_GROUP_OTHER = "other"

_MINTSIFRY_MARKERS = (
    "минцифр",
    "минкомсвяз",
    "нуц россии",
    "digital.gov.ru",
    "minsvyaz.ru",
)
_TREASURY_MARKERS = (
    "казначейств",
    "roskazna",
)


def issuer_group(issuer: Optional[str]) -> str:
    """Определить группу издателя сертификата.

    Возвращает ``mintsifry`` для УЦ Минцифры (Минкомсвязь, НУЦ России),
    ``treasury`` для УЦ Федерального казначейства и ``other`` для остальных.
    Сравнение идёт по подстроке без учёта регистра, потому что DN издателей
    отличаются порядком атрибутов и формулировками.
    """
    value = (issuer or "").lower()
    if any(marker in value for marker in _MINTSIFRY_MARKERS):
        return ISSUER_GROUP_MINTSIFRY
    if any(marker in value for marker in _TREASURY_MARKERS):
        return ISSUER_GROUP_TREASURY
    return ISSUER_GROUP_OTHER


def format_dt(value: Optional[datetime], fmt: str = "%d.%m.%Y %H:%M:%S") -> str:
    if not value:
        return "—"
    try:
        return value.strftime(fmt)
    except Exception:
        return "—"


def format_date(value: Optional[datetime]) -> str:
    return format_dt(value, "%d.%m.%Y")


def safe_filename(value: str, max_len: int = 80) -> str:
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value or "")
    value = value.strip(" .")
    if not value:
        value = "item"
    return value[:max_len]


@dataclass
class CertLocation:
    store_name: str          # My / CA / Root
    location: str            # CurrentUser / LocalMachine
    display: str             # Личные (Пользователь)
    code: str                # uMy / mMy / ...
    has_private_key: bool = False

    @property
    def admin_required(self) -> bool:
        return self.location == "LocalMachine"


@dataclass
class Certificate:
    thumbprint: str
    subject: str
    issuer: str
    cn: str
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    date_known: bool
    is_expired: bool
    has_private_key: bool
    serial: str = ""
    friendly_name: str = ""
    raw: bytes = b""
    crl_urls: List[str] = field(default_factory=list)
    ocsp_urls: List[str] = field(default_factory=list)
    ca_issuer_urls: List[str] = field(default_factory=list)
    locations: List[CertLocation] = field(default_factory=list)
    containers: List["Container"] = field(default_factory=list)
    note: str = ""
    revocation: str = "not_checked"   # good / revoked / unknown / self_signed / not_checked
    revocation_reason: str = ""
    revocation_note: str = ""

    @property
    def key(self) -> str:
        return "CERT:" + self.thumbprint

    @property
    def source_display(self) -> str:
        seen: List[str] = []
        for loc in self.locations:
            if loc.display not in seen:
                seen.append(loc.display)
        return "; ".join(seen) if seen else "—"

    @property
    def store_codes(self) -> List[str]:
        return [loc.code for loc in self.locations]

    @property
    def container_display(self) -> str:
        if not self.containers:
            return ""
        return "; ".join(c.name for c in self.containers)

    @property
    def revoked(self) -> bool:
        return self.revocation == "revoked"

    @property
    def revocation_short(self) -> str:
        return {
            "good": "Не отозван",
            "revoked": "ОТОЗВАН",
            "unknown": "Неизвестно",
            "self_signed": "Самоподписанный",
            "not_checked": "Не проверялся",
        }.get(self.revocation, "—")

    @property
    def revocation_display(self) -> str:
        text = self.revocation_short
        if self.revocation == "revoked" and self.revocation_reason:
            text += ": " + self.revocation_reason
        elif self.revocation == "unknown" and self.revocation_note:
            text += ": " + self.revocation_note
        return text

    @property
    def status(self) -> str:
        if self.revocation == "revoked":
            if self.is_expired:
                return "[!] ОТОЗВАН (ПРОСРОЧЕН)"
            return "[!] ОТОЗВАН"
        if not self.date_known:
            return "[?] ДАТА НЕИЗВЕСТНА"
        if self.is_expired:
            return "[X] ПРОСРОЧЕН"
        return "[OK] ДЕЙСТВИТЕЛЕН"

    @property
    def display_name(self) -> str:
        return self.cn or self.friendly_name or self.subject or self.thumbprint


@dataclass
class Container:
    key: str
    name: str
    kind: str                       # Registry / File / Unknown
    media: str                      # Registry / HDD / USB / Network / Unknown
    path: Optional[str] = None
    reg_path: Optional[str] = None  # HKCU\Software\... (для показа и reg.exe)
    reg_hive: Optional[str] = None  # HKCU / HKLM / HKU
    reg_subkey: Optional[str] = None
    reg_wow64: int = 0              # 0 / KEY_WOW64_32KEY / KEY_WOW64_64KEY
    full_name: Optional[str] = None # \\.\REGISTRY\... или \\.\HDD\...
    internal_name: str = ""         # имя из name.key (для файловых контейнеров)
    source: str = ""
    thumbprint: str = ""
    subject: str = ""
    not_after: Optional[datetime] = None
    date_known: bool = False
    is_expired: bool = False
    cert_found: bool = False
    orphan: Optional[bool] = None   # True/False/None (неизвестно)
    info_known: bool = True
    note: str = ""
    revocation: str = "not_checked"  # good / revoked / unknown / not_checked
    revocation_reason: str = ""
    revocation_note: str = ""
    certificate: Optional[Certificate] = None

    @property
    def display_name(self) -> str:
        return self.subject or self.name or self.path or self.reg_path or "—"

    @property
    def location_display(self) -> str:
        if self.kind == "Registry":
            return self.reg_path or self.full_name or self.name
        if self.kind == "File":
            return self.path or self.full_name or self.name
        return self.full_name or self.name

    @property
    def status(self) -> str:
        if self.orphan is True:
            return "[!] ОСИРОТЕВШИЙ (НЕТ СЕРТИФИКАТА)"
        if not self.info_known:
            return "[?] НЕТ ДАННЫХ О СЕРТИФИКАТЕ"
        if self.kind == "Registry":
            prefix = "В РЕЕСТРЕ"
        elif self.media == "USB":
            prefix = "USB/СЪЁМНЫЙ"
        elif self.media == "HDD":
            prefix = "НА ДИСКЕ"
        elif self.media == "Network":
            prefix = "В СЕТИ"
        else:
            prefix = "КОНТЕЙНЕР"
        if self.thumbprint and not self.cert_found:
            prefix += " (СЕРТИФИКАТ НЕ УСТАНОВЛЕН)"
        if self.revocation == "revoked":
            return "[!] " + prefix + " (ОТОЗВАН)"
        if not self.date_known:
            return "[?] " + prefix + " (ДАТА НЕИЗВЕСТНА)"
        if self.is_expired:
            return "[!] " + prefix + " (ПРОСРОЧЕН)"
        return "[OK] " + prefix + " (ДЕЙСТВИТЕЛЕН)"

    @property
    def is_problem(self) -> bool:
        return bool(
            self.is_expired
            or self.orphan is True
            or self.revocation == "revoked"
        )

    @property
    def revoked(self) -> bool:
        return self.revocation == "revoked"

    @property
    def revocation_short(self) -> str:
        return {
            "good": "Не отозван",
            "revoked": "ОТОЗВАН",
            "unknown": "Неизвестно",
            "self_signed": "Самоподписанный",
            "not_checked": "Не проверялся",
        }.get(self.revocation, "—")

    @property
    def revocation_display(self) -> str:
        text = self.revocation_short
        if self.revocation == "revoked" and self.revocation_reason:
            text += ": " + self.revocation_reason
        elif self.revocation == "unknown" and self.revocation_note:
            text += ": " + self.revocation_note
        return text

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
        }.get(self.media, self.media)

    @property
    def cert_display(self) -> str:
        if self.orphan is True:
            return "Нет"
        if self.cert_found:
            # Показываем, кто/что это: имя (CN), понятное имя или субъект.
            # Раньше здесь было просто «Найден», и по таблице нельзя было
            # понять, какому сертификату принадлежит контейнер.
            name = ""
            if self.certificate is not None:
                name = self.certificate.display_name or ""
            name = (name or self.subject or "").strip()
            return name or "Найден"
        if self.thumbprint:
            return "Не установлен"
        if not self.info_known:
            return "Неизвестно"
        return "Нет данных"


@dataclass
class OperationResult:
    kind: str
    name: str
    success: bool
    message: str = ""
    details: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    target_key: str = ""

    @property
    def status_text(self) -> str:
        return "OK" if self.success else "ОШИБКА"


@dataclass
class BackupSummary:
    path: str
    certs: int = 0
    containers: int = 0
    files: int = 0
    failures: int = 0
    password: str = ""
    messages: List[str] = field(default_factory=list)
    log_copy: str = ""
    cancelled: bool = False
    keys_exported: int = 0
    keys_missing: int = 0
    verified: bool = False
    verification_messages: List[str] = field(default_factory=list)
    unrestorable: List[str] = field(default_factory=list)


STORE_DEFINITIONS = [
    {"store_name": "My", "location": "CurrentUser", "display": "Личные (Пользователь)", "code": "uMy"},
    {"store_name": "My", "location": "LocalMachine", "display": "Личные (Компьютер)", "code": "mMy"},
    {"store_name": "CA", "location": "CurrentUser", "display": "Промежуточные (Пользователь)", "code": "uCA"},
    {"store_name": "CA", "location": "LocalMachine", "display": "Промежуточные (Компьютер)", "code": "mCA"},
    {"store_name": "Root", "location": "CurrentUser", "display": "Доверенные (Пользователь)", "code": "uROOT"},
    {"store_name": "Root", "location": "LocalMachine", "display": "Доверенные (Компьютер)", "code": "mROOT"},
]


def store_code(store_name: str, location: str) -> str:
    prefix = "u" if location == "CurrentUser" else "m"
    name = {"My": "My", "CA": "CA", "Root": "ROOT"}.get(store_name, store_name)
    return prefix + name
