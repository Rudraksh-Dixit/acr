"""IOC (indicator of compromise) parsing and matching.

Accepted inputs
---------------
CSV
    header with type/value columns (``type,indicator,source`` and aliases), or
    a single column of bare indicators whose type is inferred by pattern
    (IPv4/IPv6, MD5/SHA1/SHA256, else domain).
STIX 2.x
    a bundle whose ``objects`` contain ``indicator`` objects; the STIX pattern
    (``[ipv4-addr:value = '1.2.3.4']``, ``[file:HASHES.'SHA-256' = '...']``)
    is parsed into typed indicators.
JSON
    ``{"indicators": [{"type": ..., "value": ..., "source": ...}, ...]}`` or
    the bare list form.

Everything that cannot be mapped becomes a structured issue (never an
exception), mirroring the telemetry normalizer's behaviour.

Matching policy
---------------
* ``ip`` indicators match ``source_ip`` / ``destination_ip`` (exact)
* ``domain`` indicators match ``domain`` (case-insensitive)
* ``hash`` indicators match ``file_hash`` (case-insensitive)

Severity of an ``ioc_match`` detection is a fixed policy, not a metric:
file hash -> HIGH, ip/domain -> MEDIUM. No technique/tactic is asserted,
because an indicator match is not itself an ATT&CK technique.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

IOC_TYPES = ("ip", "domain", "hash")

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6 = re.compile(r"^[0-9a-f:]+$", re.IGNORECASE)
_MD5 = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
_SHA1 = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)

# `key = 'value'` comparisons inside a STIX pattern; the key may contain
# colons and quotes, e.g. file:HASHES.'SHA-256'
_STIX_COMPARE = re.compile(r"([A-Za-z0-9_.\-:'\"]+?)\s*=\s*'([^']+)'")

_TYPE_ALIASES = {
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip-address": "ip", "ip_address": "ip",
    "address": "ip", "src_ip": "ip", "dst_ip": "ip",
    "domain": "domain", "domain_name": "domain", "domain-name": "domain",
    "hostname": "domain", "dns": "domain",
    "hash": "hash", "md5": "hash", "sha1": "hash", "sha256": "hash",
    "file_hash": "hash", "file-hash": "hash", "checksum": "hash",
}


@dataclass
class Indicator:
    type: str  # ip | domain | hash
    value: str
    source: str = "unknown"
    raw: Optional[str] = None


@dataclass
class IocParseResult:
    indicators: list[Indicator] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)
    format: str = "unknown"


def infer_type(value: str) -> Optional[str]:
    """Best-effort indicator type for a bare value (None when unclear)."""
    v = value.strip()
    if _IPV4.match(v) and all(int(p) <= 255 for p in v.split(".")):
        return "ip"
    if ":" in v and _IPV6.match(v) and "." not in v:
        return "ip"
    if _MD5.match(v) or _SHA1.match(v) or _SHA256.match(v):
        return "hash"
    if _DOMAIN.match(v):
        return "domain"
    return None


def _issue(index: Optional[int], message: str, field_name: Optional[str] = None) -> dict[str, Any]:
    return {"index": index, "scope": "ioc", "field": field_name, "message": message, "source": "ioc"}


def _norm_type(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    return _TYPE_ALIASES.get(str(raw).strip().lower())


def _add(
    result: IocParseResult,
    value: Any,
    type_hint: Optional[str] = None,
    source: str = "unknown",
    index: Optional[int] = None,
) -> None:
    if value is None or str(value).strip() == "":
        result.issues.append(_issue(index, "empty indicator value", "value"))
        return
    v = str(value).strip().strip("'\"")
    itype = _norm_type(type_hint) or infer_type(v)
    if itype is None:
        result.issues.append(_issue(index, f"cannot determine indicator type for '{v[:60]}'", "value"))
        return
    result.indicators.append(Indicator(type=itype, value=v, source=source, raw=str(value)))


def parse_csv(text: str, source: str = "csv") -> IocParseResult:
    """Parse CSV indicators; header optional for single-column files.

    Column aliases: type/kind/indicator_type, value/indicator/ioc/observable,
    source/list/provider/feed. A headerless file is read as bare values, with
    the second column (when present) treated as the indicator source.
    """
    result = IocParseResult(format="csv")
    reader = csv.reader(io.StringIO(text))
    rows = [r for r in reader if any(c.strip() for c in r)]
    if not rows:
        result.issues.append(_issue(None, "CSV file is empty"))
        return result

    header = [c.strip().lower() for c in rows[0]]
    type_col = next((i for i, h in enumerate(header)
                     if h in ("type", "kind", "indicator_type", "ioc_type")), None)
    value_col = next((i for i, h in enumerate(header)
                      if h in ("value", "indicator", "ioc", "observable", "artifact", "data")), None)
    source_col = next((i for i, h in enumerate(header)
                       if h in ("source", "list", "provider", "feed", "dataset")), None)

    start = 1
    if type_col is None and value_col is None:
        start = 0                      # headerless: every row is data
        value_col = 0
    elif value_col is None:
        result.issues.append(_issue(0, f"CSV header has no value column: {header}", "header"))
        return result
    elif type_col is None:
        # header without a type column; if row 1's value cell is actually an
        # indicator, the "header" was data all along
        cell = rows[0][value_col] if value_col < len(rows[0]) else ""
        if infer_type(cell):
            start = 0
            type_col = None

    for i, row in enumerate(rows[start:], start=start + 1):
        if value_col >= len(row):
            result.issues.append(_issue(i, "row has too few columns"))
            continue
        row_source = source
        if source_col is not None and source_col < len(row) and row[source_col].strip():
            row_source = row[source_col].strip()
        elif type_col is None and source_col is None and len(row) > 1 and value_col == 0:
            candidate = row[1].strip()
            if candidate and not infer_type(candidate):
                row_source = candidate  # headerless value,source layout
        row_type = row[type_col].strip() if type_col is not None and type_col < len(row) else None
        _add(result, row[value_col], row_type, row_source, i)
    return result


def parse_stix(text: str) -> IocParseResult:
    """Parse a STIX 2.x bundle, a JSON indicator list, or a bare STIX pattern."""
    result = IocParseResult(format="stix")
    try:
        payload = json.loads(text)
    except ValueError as exc:
        # maybe the whole payload is a single STIX pattern string
        if text.strip().startswith("[") and " = '" in text:
            return parse_stix_pattern(text.strip(), source="stix")
        result.issues.append(_issue(None, f"invalid JSON: {exc}"))
        return result

    if isinstance(payload, str):
        return parse_stix_pattern(payload, source="stix")
    if isinstance(payload, dict) and isinstance(payload.get("indicators"), list):
        res = parse_json_indicators(payload["indicators"], source=str(payload.get("source") or "json"))
        res.format = "json"
        return res
    if isinstance(payload, list):
        if payload and all(isinstance(x, dict) and "value" in x for x in payload):
            res = parse_json_indicators(payload, source="json")
            res.format = "json"
            return res
        payload = {"type": "bundle", "objects": payload}
    if not isinstance(payload, dict):
        result.issues.append(_issue(None, "payload is not a STIX bundle, list or pattern"))
        return result
    if payload.get("type") != "bundle":
        result.issues.append(_issue(None, "not a STIX bundle (missing 'type: bundle')"))
        return result

    objects = payload.get("objects") or []
    if not isinstance(objects, list):
        result.issues.append(_issue(None, "'objects' must be a list"))
        return result
    for i, obj in enumerate(objects):
        if not isinstance(obj, dict):
            result.issues.append(_issue(i, "object is not a mapping"))
            continue
        if obj.get("type") != "indicator":
            continue  # only indicator objects carry patterns
        pattern = str(obj.get("pattern") or "")
        if not pattern:
            result.issues.append(_issue(i, "indicator object has no pattern", "pattern"))
            continue
        src = str(obj.get("source") or obj.get("name") or "stix")[:120]
        before = len(result.indicators)
        _parse_stix_pattern_into(result, pattern, src)
        if len(result.indicators) == before:
            result.issues.append(_issue(i, f"no recognisable value in pattern: {pattern[:80]}", "pattern"))
    if not result.indicators and not result.issues:
        result.issues.append(_issue(None, "bundle contains no indicator objects"))
    return result


def parse_stix_pattern(pattern: str, source: str = "stix") -> IocParseResult:
    result = IocParseResult(format="stix")
    _parse_stix_pattern_into(result, pattern, source)
    if not result.indicators:
        result.issues.append(_issue(None, f"no recognisable value in pattern: {pattern[:80]}", "pattern"))
    return result


def _parse_stix_pattern_into(result: IocParseResult, pattern: str, source: str) -> None:
    for key, value in _STIX_COMPARE.findall(pattern):
        k = key.lower().strip("'\"")
        if "ipv4" in k or "ipv6" in k:
            _add(result, value, "ip", source)
        elif "domain" in k:
            _add(result, value, "domain", source)
        elif "hashes" in k or k.startswith("file:"):
            _add(result, value, "hash", source)
        else:
            _add(result, value, None, source)  # e.g. `:value` keys: infer


def parse_json_indicators(items: Iterable[Any], source: str = "json") -> IocParseResult:
    result = IocParseResult(format="json")
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            _add(result, item, None, source, i)
            continue
        _add(
            result,
            item.get("value") or item.get("indicator") or item.get("observable"),
            item.get("type") or item.get("indicator_type"),
            str(item.get("source") or source),
            i,
        )
    if not result.indicators and not result.issues:
        result.issues.append(_issue(None, "no indicators found"))
    return result


def parse_ioc_payload(
    content: str,
    fmt: str = "auto",
    filename: Optional[str] = None,
    default_source: str = "upload",
) -> IocParseResult:
    """Parse indicator content in any supported format.

    ``fmt='auto'`` sniffs: leading ``{``/``[`` -> JSON/STIX, otherwise CSV.
    Indicator rows that carry no explicit source get ``filename`` (when the
    caller knows it) or ``default_source``.
    """
    text = content.lstrip("﻿")
    chosen = (fmt or "auto").lower()
    if chosen == "auto":
        chosen = "stix" if text.lstrip()[:1] in ("{", "[") else "csv"

    if chosen == "csv":
        res = parse_csv(text, source=filename or default_source)
    elif chosen in ("stix", "json"):
        res = parse_stix(text)
        res.format = chosen if chosen == "json" else res.format
    else:
        res = IocParseResult(format=chosen)
        res.issues.append(_issue(None, f"unknown format '{fmt}' (use auto, csv, stix or json)"))
    if not text.strip():
        res.issues.append(_issue(None, "empty payload"))
        return res

    # dedupe identical (type, value, source) triples within one import
    seen: set[tuple[str, str, str]] = set()
    unique: list[Indicator] = []
    for ind in res.indicators:
        key = (ind.type, ind.value if ind.type == "ip" else ind.value.lower(), ind.source)
        if key in seen:
            res.issues.append(_issue(None, f"duplicate indicator skipped: {ind.value[:60]}", "value"))
            continue
        seen.add(key)
        unique.append(ind)
    res.indicators = unique
    return res


def match_events(events: Iterable[dict[str, Any]], indicators: Iterable[Indicator]) -> list[dict[str, Any]]:
    """Return one match record per (event, indicator) hit."""
    ip_values = {i.value for i in indicators if i.type == "ip"}
    domain_values = {i.value.lower() for i in indicators if i.type == "domain"}
    hash_values = {i.value.lower() for i in indicators if i.type == "hash"}
    by_ip = {i.value: i for i in indicators if i.type == "ip"}
    by_domain = {i.value.lower(): i for i in indicators if i.type == "domain"}
    by_hash = {i.value.lower(): i for i in indicators if i.type == "hash"}

    matches: list[dict[str, Any]] = []
    for event in events:
        hits: list[tuple[str, Indicator, str]] = []
        for field_name in ("source_ip", "destination_ip"):
            v = event.get(field_name)
            if v and v in ip_values:
                hits.append((field_name, by_ip[v], v))
        dom = event.get("domain")
        if dom and dom.lower() in domain_values:
            hits.append(("domain", by_domain[dom.lower()], dom))
        fhash = event.get("file_hash")
        if fhash and fhash.lower() in hash_values:
            hits.append(("file_hash", by_hash[fhash.lower()], fhash))
        for field_name, indicator, observed in hits:
            matches.append({
                "event_id": event.get("event_id"),
                "field": field_name,
                "indicator_type": indicator.type,
                "indicator_value": indicator.value,
                "indicator_source": indicator.source,
                "observed_value": observed,
                "host": event.get("host"),
                "scenario_id": event.get("scenario_id"),
            })
    return matches
