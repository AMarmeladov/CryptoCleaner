"""Низкоуровневый доступ к хранилищам сертификатов Windows через crypt32.dll.

Модуль не требует pywin32 и работает на Python 3.8+ (Windows 7-11, Server 2012-2025).
"""
from __future__ import annotations

import ctypes
import os
from ctypes import POINTER, byref, create_unicode_buffer, wintypes
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from .revocation import certificate_revocation_urls

# ---------------------------------------------------------------------------
# Константы CryptoAPI
# ---------------------------------------------------------------------------
CERT_STORE_PROV_SYSTEM_W = 10
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
CERT_STORE_READONLY_FLAG = 0x00008000

CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_ISSUER_FLAG = 0x00000001
CERT_X500_NAME_STR = 3

CERT_SHA1_HASH_PROP_ID = 3
CERT_KEY_PROV_INFO_PROP_ID = 2
CERT_KEY_CONTEXT_PROP_ID = 5
CERT_FRIENDLY_NAME_PROP_ID = 11

CRYPT_E_NOT_FOUND = 0x80092004
ERROR_ACCESS_DENIED = 5

# --- Проверка отзыва (CertVerifyRevocation) --------------------------------
CERT_CONTEXT_REVOCATION_TYPE = 1
CERT_VERIFY_REV_CHAIN_FLAG = 0x00000001
CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION = 0x00000002
CERT_VERIFY_REV_ACCUMULATIVE_TIMEOUT_FLAG = 0x00000004

CRYPT_E_REVOKED = 0x80092010
CRYPT_E_NO_REVOCATION_DLL = 0x80092011
CRYPT_E_NO_REVOCATION_CHECK = 0x80092012
CRYPT_E_REVOCATION_OFFLINE = 0x80092013
CRYPT_E_REVOCATION_CHECK_FAILED = 0x80092014

CRL_REASON_UNSPECIFIED = 0
CRL_REASON_KEY_COMPROMISE = 1
CRL_REASON_CA_COMPROMISE = 2
CRL_REASON_AFFILIATION_CHANGED = 3
CRL_REASON_SUPERSEDED = 4
CRL_REASON_CESSATION_OF_OPERATION = 5
CRL_REASON_CERTIFICATE_HOLD = 6
CRL_REASON_REMOVE_FROM_CRL = 8
CRL_REASON_PRIVILEGE_WITHDRAWN = 9
CRL_REASON_AA_COMPROMISE = 10

REVOCATION_REASONS = {
    CRL_REASON_UNSPECIFIED: "причина не указана",
    CRL_REASON_KEY_COMPROMISE: "компрометация ключа",
    CRL_REASON_CA_COMPROMISE: "компрометация удостоверяющего центра",
    CRL_REASON_AFFILIATION_CHANGED: "изменение принадлежности",
    CRL_REASON_SUPERSEDED: "сертификат заменён",
    CRL_REASON_CESSATION_OF_OPERATION: "прекращение деятельности",
    CRL_REASON_CERTIFICATE_HOLD: "временная блокировка",
    CRL_REASON_REMOVE_FROM_CRL: "исключён из CRL",
    CRL_REASON_PRIVILEGE_WITHDRAWN: "отозваны полномочия",
    CRL_REASON_AA_COMPROMISE: "компрометация атрибутного центра",
}

# ---------------------------------------------------------------------------
# Структуры
# ---------------------------------------------------------------------------
class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class CRYPT_INTEGER_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", POINTER(ctypes.c_ubyte)),
    ]


class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
    _fields_ = [
        ("pszObjId", ctypes.c_char_p),
        ("Parameters", CRYPT_INTEGER_BLOB),
    ]


class CRYPT_BIT_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", POINTER(ctypes.c_ubyte)),
        ("cUnusedBits", wintypes.DWORD),
    ]


class CERT_PUBLIC_KEY_INFO(ctypes.Structure):
    _fields_ = [
        ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("PublicKey", CRYPT_BIT_BLOB),
    ]


class CERT_EXTENSION(ctypes.Structure):
    _fields_ = [
        ("pszObjId", ctypes.c_char_p),
        ("fCritical", wintypes.BOOL),
        ("Value", CRYPT_INTEGER_BLOB),
    ]


class CERT_INFO(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", CRYPT_INTEGER_BLOB),
        ("NotBefore", FILETIME),
        ("NotAfter", FILETIME),
        ("Subject", CRYPT_INTEGER_BLOB),
        ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
        ("IssuerUniqueId", CRYPT_BIT_BLOB),
        ("SubjectUniqueId", CRYPT_BIT_BLOB),
        ("cExtension", wintypes.DWORD),
        ("rgExtension", POINTER(CERT_EXTENSION)),
    ]


class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", POINTER(CERT_INFO)),
        ("hCertStore", wintypes.HANDLE),
    ]


class CERT_REVOCATION_PARA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("pIssuerCert", POINTER(CERT_CONTEXT)),
        ("cCertStore", wintypes.DWORD),
        ("rgCertStore", POINTER(wintypes.HANDLE)),
        ("hCrlStore", wintypes.HANDLE),
        ("pftTimeToUse", POINTER(FILETIME)),
        ("dwUrlRetrievalTimeout", wintypes.DWORD),
        ("fCheckUrlRetrievalTimeout", wintypes.BOOL),
    ]


class CERT_REVOCATION_STATUS(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("dwError", wintypes.DWORD),
        ("dwReason", wintypes.DWORD),
        ("fHasFreshnessTime", wintypes.BOOL),
        ("dwFreshnessTime", wintypes.DWORD),
    ]


# ---------------------------------------------------------------------------
# DLL и прототипы
# ---------------------------------------------------------------------------
crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

crypt32.CertOpenStore.argtypes = [
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.c_void_p,
]
crypt32.CertOpenStore.restype = wintypes.HANDLE

crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
crypt32.CertCloseStore.restype = wintypes.BOOL

crypt32.CertEnumCertificatesInStore.argtypes = [
    wintypes.HANDLE,
    POINTER(CERT_CONTEXT),
]
crypt32.CertEnumCertificatesInStore.restype = POINTER(CERT_CONTEXT)

crypt32.CertDeleteCertificateFromStore.argtypes = [POINTER(CERT_CONTEXT)]
crypt32.CertDeleteCertificateFromStore.restype = wintypes.BOOL

crypt32.CertGetNameStringW.argtypes = [
    POINTER(CERT_CONTEXT),
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPWSTR,
    wintypes.DWORD,
]
crypt32.CertGetNameStringW.restype = wintypes.DWORD

crypt32.CertNameToStrW.argtypes = [
    wintypes.DWORD,
    POINTER(CRYPT_INTEGER_BLOB),
    wintypes.DWORD,
    wintypes.LPWSTR,
    wintypes.DWORD,
]
crypt32.CertNameToStrW.restype = wintypes.DWORD

crypt32.CertGetCertificateContextProperty.argtypes = [
    POINTER(CERT_CONTEXT),
    wintypes.DWORD,
    ctypes.c_void_p,
    POINTER(wintypes.DWORD),
]
crypt32.CertGetCertificateContextProperty.restype = wintypes.BOOL

crypt32.CertCreateCertificateContext.argtypes = [
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
]
crypt32.CertCreateCertificateContext.restype = POINTER(CERT_CONTEXT)

crypt32.CertFreeCertificateContext.argtypes = [POINTER(CERT_CONTEXT)]
crypt32.CertFreeCertificateContext.restype = wintypes.BOOL

crypt32.CertVerifyRevocation.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    POINTER(ctypes.c_void_p),
    wintypes.DWORD,
    POINTER(CERT_REVOCATION_PARA),
    POINTER(CERT_REVOCATION_STATUS),
]
crypt32.CertVerifyRevocation.restype = wintypes.BOOL

kernel32.GetLogicalDriveStringsW.argtypes = [wintypes.DWORD, wintypes.LPWSTR]
kernel32.GetLogicalDriveStringsW.restype = wintypes.DWORD
kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
kernel32.GetDriveTypeW.restype = wintypes.UINT


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------
def _filetime_to_datetime(ft: FILETIME) -> Optional[datetime]:
    value = (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)
    if not value:
        return None
    try:
        utc = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=value // 10
        )
        return utc.astimezone().replace(tzinfo=None)
    except Exception:
        return None


def _blob_to_hex(blob: CRYPT_INTEGER_BLOB) -> str:
    if not blob.pbData or not blob.cbData:
        return ""
    try:
        data = ctypes.string_at(blob.pbData, int(blob.cbData))
        return data[::-1].hex().upper()
    except Exception:
        return ""


def _get_simple_name(ctx, issuer: bool = False) -> str:
    flags = CERT_NAME_ISSUER_FLAG if issuer else 0
    try:
        size = crypt32.CertGetNameStringW(
            ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None, 0
        )
        if size <= 1:
            return ""
        buf = create_unicode_buffer(size)
        crypt32.CertGetNameStringW(
            ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, buf, size
        )
        return buf.value or ""
    except Exception:
        return ""


def _get_full_name(ctx, issuer: bool = False) -> str:
    try:
        info = ctx.contents.pCertInfo.contents
        blob = info.Issuer if issuer else info.Subject
        size = crypt32.CertNameToStrW(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            byref(blob),
            CERT_X500_NAME_STR,
            None,
            0,
        )
        if size <= 1:
            return _get_simple_name(ctx, issuer)
        buf = create_unicode_buffer(size)
        crypt32.CertNameToStrW(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            byref(blob),
            CERT_X500_NAME_STR,
            buf,
            size,
        )
        return buf.value or _get_simple_name(ctx, issuer)
    except Exception:
        return _get_simple_name(ctx, issuer)


def _get_hash(ctx) -> str:
    try:
        size = wintypes.DWORD(0)
        if not crypt32.CertGetCertificateContextProperty(
            ctx, CERT_SHA1_HASH_PROP_ID, None, byref(size)
        ):
            return ""
        if size.value <= 0:
            return ""
        buf = (ctypes.c_ubyte * size.value)()
        if not crypt32.CertGetCertificateContextProperty(
            ctx, CERT_SHA1_HASH_PROP_ID, buf, byref(size)
        ):
            return ""
        return bytes(buf).hex().upper()
    except Exception:
        return ""


def _get_friendly_name(ctx) -> str:
    try:
        size = wintypes.DWORD(0)
        if not crypt32.CertGetCertificateContextProperty(
            ctx, CERT_FRIENDLY_NAME_PROP_ID, None, byref(size)
        ):
            return ""
        if size.value < 2:
            return ""
        buf = create_unicode_buffer(max(2, size.value // 2))
        if not crypt32.CertGetCertificateContextProperty(
            ctx, CERT_FRIENDLY_NAME_PROP_ID, buf, byref(size)
        ):
            return ""
        return buf.value or ""
    except Exception:
        return ""


def _has_private_key(ctx) -> bool:
    for prop in (CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_CONTEXT_PROP_ID):
        try:
            size = wintypes.DWORD(0)
            if crypt32.CertGetCertificateContextProperty(
                ctx, prop, None, byref(size)
            ):
                return True
        except Exception:
            pass
    return False


def _read_context(ctx) -> Optional[Dict]:
    try:
        info = ctx.contents.pCertInfo.contents
        thumb = _get_hash(ctx)
        if not thumb:
            return None
        raw = b""
        try:
            if ctx.contents.pbCertEncoded and ctx.contents.cbCertEncoded:
                raw = ctypes.string_at(
                    ctx.contents.pbCertEncoded, int(ctx.contents.cbCertEncoded)
                )
        except Exception:
            raw = b""
        urls = certificate_revocation_urls(raw)
        return {
            "thumbprint": thumb,
            "subject": _get_full_name(ctx, False),
            "issuer": _get_full_name(ctx, True),
            "cn": _get_simple_name(ctx, False),
            "not_before": _filetime_to_datetime(info.NotBefore),
            "not_after": _filetime_to_datetime(info.NotAfter),
            "serial": _blob_to_hex(info.SerialNumber),
            "friendly_name": _get_friendly_name(ctx),
            "has_private_key": _has_private_key(ctx),
            "raw": raw,
            "crl_urls": urls.get("crl", []),
            "ocsp_urls": urls.get("ocsp", []),
            "ca_issuer_urls": urls.get("ca_issuers", []),
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Публичный API
# ---------------------------------------------------------------------------
def open_store(
    store_name: str, location: str, readonly: bool = True
) -> int:
    """Открыть системное хранилище. location: CurrentUser / LocalMachine."""
    flags = (
        CERT_SYSTEM_STORE_CURRENT_USER
        if location.lower() == "currentuser"
        else CERT_SYSTEM_STORE_LOCAL_MACHINE
    )
    if readonly:
        flags |= CERT_STORE_READONLY_FLAG
    flags |= CERT_STORE_OPEN_EXISTING_FLAG
    h = crypt32.CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        None,
        flags,
        ctypes.cast(ctypes.c_wchar_p(store_name), ctypes.c_void_p),
    )
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(h)


def close_store(handle: int) -> None:
    try:
        crypt32.CertCloseStore(handle, 0)
    except Exception:
        pass


def enum_certificates(store_name: str, location: str) -> List[Dict]:
    """Вернуть список сертификатов из хранилища."""
    try:
        handle = open_store(store_name, location, readonly=True)
    except OSError:
        return []
    result: List[Dict] = []
    try:
        ctx = crypt32.CertEnumCertificatesInStore(handle, None)
        while ctx:
            item = _read_context(ctx)
            if item:
                result.append(item)
            ctx = crypt32.CertEnumCertificatesInStore(handle, ctx)
    finally:
        close_store(handle)
    return result


def cert_present(store_name: str, location: str, thumbprint: str) -> bool:
    thumb = (thumbprint or "").replace(" ", "").upper()
    if not thumb:
        return False
    for item in enum_certificates(store_name, location):
        if item["thumbprint"] == thumb:
            return True
    return False


def _context_from_raw(raw: bytes):
    if not raw:
        return None
    try:
        buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        ctx = crypt32.CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            buffer,
            len(raw),
        )
        return ctx or None
    except Exception:
        return None


def verify_revocation(
    cert_raw: bytes,
    issuer_raw: bytes = b"",
    timeout_ms: int = 3000,
    cache_only: bool = False,
) -> Dict[str, object]:
    """Проверить отзыв сертификата через CertVerifyRevocation (CryptoAPI).

    Возвращает словарь:
        status: "good" | "revoked" | "unknown"
        reason: текст причины отзыва (если известна)
        message: человекочитаемое пояснение
        code: код ошибки Windows (0 при успехе)
        freshness: возраст CRL в секундах (0, если неизвестен)

    Параметр issuer_raw оставлен для совместимости и не используется:
    издателя надёжнее находит сам CryptoAPI (см. комментарий ниже).
    timeout_ms не передаётся в API (Windows игнорирует его вместе с
    fCheckUrlRetrievalTimeout); ограничение времени делает вызывающий код.

    Честность: если CRL/OCSP недоступны или проверка не выполнена,
    возвращается "unknown", а не "good".
    """
    unknown = {
        "status": "unknown",
        "reason": "",
        "message": "",
        "code": 0,
        "freshness": 0,
    }
    if not cert_raw:
        result = dict(unknown)
        result["message"] = "Нет DER-данных сертификата"
        return result

    cert_ctx = _context_from_raw(cert_raw)
    if not cert_ctx:
        result = dict(unknown)
        result["message"] = "Не удалось создать контекст сертификата"
        return result

    # Издателя намеренно не передаём: CryptoAPI сам находит его в системных
    # хранилищах и для ГОСТ-сертификатов использует цепочку/провайдера
    # КриптоПро. Если передать pIssuerCert вручную, проверка ГОСТ-CRL может
    # завершиться ошибкой.
    #
    # fCheckUrlRetrievalTimeout=True на практике заставляет Windows вернуть
    # CRYPT_E_REVOCATION_OFFLINE сразу, не пытаясь скачать CRL, поэтому
    # используем штатный таймаут CryptoAPI (по умолчанию 15 с на URL).
    para = CERT_REVOCATION_PARA()
    para.cbSize = ctypes.sizeof(para)
    para.pIssuerCert = None
    para.dwUrlRetrievalTimeout = 0
    para.fCheckUrlRetrievalTimeout = False

    status = CERT_REVOCATION_STATUS()
    status.cbSize = ctypes.sizeof(status)
    contexts = (ctypes.c_void_p * 1)(ctypes.cast(cert_ctx, ctypes.c_void_p))
    flags = CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION if cache_only else 0

    try:
        ctypes.set_last_error(0)
        ok = crypt32.CertVerifyRevocation(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CERT_CONTEXT_REVOCATION_TYPE,
            1,
            contexts,
            flags,
            byref(para),
            byref(status),
        )
        if ok:
            result = dict(unknown)
            result["status"] = "good"
            result["message"] = "Сертификат не отозван"
            if status.fHasFreshnessTime:
                result["freshness"] = int(status.dwFreshnessTime)
            return result

        code = int(status.dwError) or ctypes.get_last_error()
        code = int(code) & 0xFFFFFFFF
        result = dict(unknown)
        result["code"] = code
        if code == CRYPT_E_REVOKED:
            reason = int(status.dwReason)
            result["status"] = "revoked"
            result["reason"] = REVOCATION_REASONS.get(
                reason, "код причины %d" % reason
            )
            result["message"] = "Сертификат отозван: %s" % result["reason"]
        elif code == CRYPT_E_REVOCATION_OFFLINE:
            result["message"] = (
                "Нет связи с сервером CRL/OCSP — статус отзыва неизвестен"
            )
        elif code == CRYPT_E_NO_REVOCATION_CHECK:
            result["message"] = (
                "Не найдена точка проверки отзыва (CRL/OCSP) — "
                "статус отзыва неизвестен"
            )
        elif code == CRYPT_E_NO_REVOCATION_DLL:
            result["message"] = (
                "Недоступен модуль проверки отзыва — статус неизвестен"
            )
        elif code == CRYPT_E_REVOCATION_CHECK_FAILED:
            result["message"] = (
                "Проверка отзыва завершилась ошибкой — статус неизвестен"
            )
        elif code == ERROR_ACCESS_DENIED:
            result["message"] = "Нет доступа к проверке отзыва"
        else:
            result["message"] = (
                "Не удалось проверить отзыв (код 0x%08X)" % code
            )
        return result
    except Exception as exc:
        result = dict(unknown)
        result["message"] = "Ошибка проверки отзыва: %s" % exc
        return result
    finally:
        try:
            crypt32.CertFreeCertificateContext(cert_ctx)
        except Exception:
            pass


def delete_certificate(store_name: str, location: str, thumbprint: str) -> int:
    """Удалить сертификат через CertDeleteCertificateFromStore.

    Возвращает количество удалённых контекстов. Бросает OSError при ошибке.
    """
    thumb = (thumbprint or "").replace(" ", "").upper()
    if not thumb:
        return 0
    handle = open_store(store_name, location, readonly=False)
    deleted = 0
    try:
        for _ in range(20):
            found = None
            ctx = crypt32.CertEnumCertificatesInStore(handle, None)
            while ctx:
                if _get_hash(ctx) == thumb:
                    found = ctx
                    break
                ctx = crypt32.CertEnumCertificatesInStore(handle, ctx)
            if not found:
                break
            if not crypt32.CertDeleteCertificateFromStore(found):
                err = ctypes.get_last_error()
                if err == CRYPT_E_NOT_FOUND:
                    break
                raise ctypes.WinError(err)
            deleted += 1
        return deleted
    finally:
        close_store(handle)


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_logical_drives() -> List[str]:
    try:
        size = 1024
        buf = create_unicode_buffer(size)
        length = kernel32.GetLogicalDriveStringsW(size, buf)
        if not length:
            return []
        raw = buf[:length]
        return [part for part in raw.split("\x00") if part]
    except Exception:
        return []


def get_drive_type(root: str) -> int:
    try:
        return int(kernel32.GetDriveTypeW(root))
    except Exception:
        return 0


DRIVE_TYPE_NAMES = {
    0: "Неизвестно",
    1: "Нет корня",
    2: "Съёмный",
    3: "HDD",
    4: "Сеть",
    5: "CD/DVD",
    6: "RAM",
}


def get_current_sid() -> str:
    """SID текущего пользователя."""
    try:
        advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            POINTER(wintypes.HANDLE),
        ]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            POINTER(ctypes.c_wchar_p),
        ]
        advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE

        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), 0x0008, byref(token)
        ):
            return ""
        try:
            size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(token, 1, None, 0, byref(size))
            if not size.value:
                return ""
            buf = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(
                token, 1, buf, size.value, byref(size)
            ):
                return ""
            # TOKEN_USER: SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; }
            sid_ptr = ctypes.cast(buf, POINTER(ctypes.c_void_p))[0]
            str_ptr = ctypes.c_wchar_p()
            if not advapi32.ConvertSidToStringSidW(sid_ptr, byref(str_ptr)):
                return ""
            try:
                return str_ptr.value or ""
            finally:
                if str_ptr:
                    kernel32.LocalFree(ctypes.cast(str_ptr, ctypes.c_void_p))
        finally:
            kernel32.CloseHandle(token)
    except Exception:
        return ""


def system_tool(name: str) -> str:
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    sysnative = os.path.join(sysroot, "Sysnative", name)
    if os.path.exists(sysnative):
        return sysnative
    return os.path.join(sysroot, "System32", name)


def set_dpi_awareness() -> None:
    """Включить максимально точное масштабирование (Per-Monitor V2)."""
    # Windows 10 1703+: PER_MONITOR_AWARE_V2
    try:
        user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
        if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return
    except Exception:
        pass
    # Windows 8.1+: PROCESS_PER_MONITOR_DPI_AWARE
    try:
        if int(ctypes.windll.shcore.SetProcessDpiAwareness(2)) == 0:
            return
    except Exception:
        pass
    # Windows 7 / Vista: системное масштабирование
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass


def get_current_user() -> str:
    """Домен\\пользователь текущего процесса."""
    try:
        advapi32.GetUserNameW.argtypes = [
            wintypes.LPWSTR,
            POINTER(wintypes.DWORD),
        ]
        advapi32.GetUserNameW.restype = wintypes.BOOL
        size = wintypes.DWORD(257)
        buf = create_unicode_buffer(size.value)
        if not advapi32.GetUserNameW(buf, byref(size)):
            return ""
        name = buf.value or ""
        domain = os.environ.get("USERDOMAIN", "")
        if domain and name:
            return domain + "\\" + name
        return name
    except Exception:
        return os.environ.get("USERNAME", "")


def set_app_user_model_id(app_id: str = "AMarmeladov.CryptoCleaner") -> None:
    """Явный AppUserModelID: правильная иконка на панели задач Windows."""
    try:
        shell32.SetCurrentProcessExplicitAppUserModelID.argtypes = [
            wintypes.LPCWSTR
        ]
        shell32.SetCurrentProcessExplicitAppUserModelID.restype = ctypes.c_long
        shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    except Exception:
        pass


def message_box(text: str, title: str = "CertCleaner", flags: int = 0x40) -> int:
    """flags: 0x04 Yes/No, 0x40 Info, 0x30 Warning, 0x10 Error."""
    try:
        return int(user32.MessageBoxW(None, text, title, flags))
    except Exception:
        return 0
