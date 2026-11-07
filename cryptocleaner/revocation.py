"""Точки проверки отзыва (CRL/OCSP) из DER-сертификата.

Модуль только читает расширения CDP (2.5.29.31) и AIA
(1.3.6.1.5.5.7.1.1) и извлекает из них URL. Сетевых запросов он не делает:
это нужно лишь для того, чтобы показать пользователю, куда именно
CryptoAPI будет обращаться при проверке отзыва.
"""
from __future__ import annotations

from typing import Dict, Iterator, List, Tuple

_CDP_OID = "2.5.29.31"
_AIA_OID = "1.3.6.1.5.5.7.1.1"
_OCSP_OID = "1.3.6.1.5.5.7.48.1"
_CA_ISSUERS_OID = "1.3.6.1.5.5.7.48.2"


def _tlv(data: bytes, pos: int = 0) -> Tuple[int, bytes, int]:
    """Прочитать один DER TLV и вернуть (тег, содержимое, следующая позиция)."""
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or pos + count > len(data):
            raise ValueError("некорректная длина DER")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("выход за границу DER")
    return tag, data[pos:end], end


def _children(data: bytes) -> Iterator[Tuple[int, bytes]]:
    pos = 0
    while pos < len(data):
        tag, value, pos = _tlv(data, pos)
        yield tag, value


def _oid_to_str(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    acc = 0
    for byte in raw[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def _collect_uri(data: bytes) -> List[str]:
    """Рекурсивно собрать GeneralName с тегом [6] (uniformResourceIdentifier)."""
    urls: List[str] = []
    for tag, value in _children(data):
        if tag == 0x86:
            urls.append(value.decode("latin-1"))
        elif tag & 0x20:
            urls.extend(_collect_uri(value))
    return urls


def _extensions(raw: bytes) -> Iterator[Tuple[str, bytes]]:
    """Перебрать расширения сертификата: (OID, содержимое OCTET STRING)."""
    _, cert_seq, _ = _tlv(raw)
    _, tbs, _ = _tlv(cert_seq)
    for tag, value in _children(tbs):
        if tag != 0xA3:  # [3] extensions
            continue
        _, extensions, _ = _tlv(value)
        for _, extension in _children(extensions):
            parts = list(_children(extension))
            if len(parts) < 2:
                continue
            yield _oid_to_str(parts[0][1]), parts[-1][1]


def _aia_urls(value: bytes) -> Tuple[List[str], List[str]]:
    """Разобрать AuthorityInfoAccessSyntax на OCSP и CA Issuers URL."""
    ocsp: List[str] = []
    ca_issuers: List[str] = []
    _, sequence, _ = _tlv(value)
    for _, description in _children(sequence):
        parts = list(_children(description))
        if len(parts) < 2:
            continue
        method = _oid_to_str(parts[0][1])
        location_tag, location_value = parts[1]
        if location_tag == 0x86:
            urls = [location_value.decode("latin-1")]
        else:
            urls = _collect_uri(location_value)
        if method == _OCSP_OID:
            ocsp.extend(urls)
        elif method == _CA_ISSUERS_OID:
            ca_issuers.extend(urls)
    return ocsp, ca_issuers


def certificate_revocation_urls(raw: bytes) -> Dict[str, List[str]]:
    """Вернуть точки проверки отзыва из DER-сертификата.

    Результат: {"crl": [...], "ocsp": [...], "ca_issuers": [...]}.
    При любой ошибке разбора возвращаются пустые списки.
    """
    result: Dict[str, List[str]] = {"crl": [], "ocsp": [], "ca_issuers": []}
    if not raw:
        return result
    try:
        for oid, value in _extensions(raw):
            if oid == _CDP_OID:
                for url in _collect_uri(value):
                    if url not in result["crl"]:
                        result["crl"].append(url)
            elif oid == _AIA_OID:
                ocsp, ca_issuers = _aia_urls(value)
                for url in ocsp:
                    if url not in result["ocsp"]:
                        result["ocsp"].append(url)
                for url in ca_issuers:
                    if url not in result["ca_issuers"]:
                        result["ca_issuers"].append(url)
    except Exception:
        return {"crl": [], "ocsp": [], "ca_issuers": []}
    return result
