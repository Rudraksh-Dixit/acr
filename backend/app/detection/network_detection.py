"""Network-centric detection rules (C2 channels, DNS anomalies)."""
from __future__ import annotations

import ipaddress
from typing import Any, Optional

from app.detection.base import (
    SCRIPT_INTERPRETERS,
    DetectionRule,
    RuleContext,
    RuleMatch,
    evidence,
    make_match,
)

MALICIOUS_IPS = {"185.220.101.45", "45.155.205.233", "91.219.236.19"}
MALICIOUS_DOMAINS = {"update-cdn-live.net", "cdn-update-check.net", "mail-secure-login.com", "fast-dl-host.net"}
HIGH_RISK_PORTS = {4444, 5555, 8080, 8443, 1337, 9001, 6667}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast


class UnusualOutboundConnectionRule(DetectionRule):
    rule_id = "UNUSUAL_OUTBOUND_CONNECTION"
    rule_name = "Outbound connection from a script/office process"
    description = "A non-browser process opened a connection to an external address."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "NETWORK_CONNECTION":
            return None
        dst = event.get("destination_ip") or ""
        if not dst or _is_private(dst):
            return None
        proc = (event.get("process_name") or event.get("parent_process") or "").lower()
        port = event.get("destination_port")
        known_bad = dst in MALICIOUS_IPS
        suspicious_proc = proc in SCRIPT_INTERPRETERS or proc in {
            "curl.exe", "wget.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe"
        }
        high_port = port in HIGH_RISK_PORTS
        if not (known_bad or suspicious_proc or high_port):
            return None
        severity = "HIGH" if (known_bad or high_port) else "MEDIUM"
        return make_match(
            self, event, severity=severity, technique_id="T1071.001",
            technique_name="Application Layer Protocol: Web Protocols",
            title=f"Outbound connection {proc or 'unknown'} -> {dst}:{port or '?'}",
            description=(
                f"{proc or 'Unknown process'} connected to external address {dst}"
                f"{f' on port {port}' if port else ''}."
                + (" Destination matches a known-malicious indicator." if known_bad else "")
            ),
            ev=[evidence("destination_ip", dst, "external destination"),
                evidence("destination_port", port, "service port"),
                evidence("process_name", proc, "initiating process"),
                evidence("protocol", event.get("protocol"), "transport")],
        )


class DnsTunnelingRule(DetectionRule):
    rule_id = "SUSPICIOUS_DNS_QUERY"
    rule_name = "Suspicious DNS query"
    description = "Unusually long DNS query or a domain matching a known-bad indicator."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "DNS_QUERY":
            return None
        query = (event.get("domain") or "").lower()
        if not query:
            return None
        known_bad = query in MALICIOUS_DOMAINS or any(query.endswith("." + d) for d in MALICIOUS_DOMAINS)
        long_query = len(query) >= ctx.settings.suspicious_dns_length
        long_labels = any(len(label) > 40 for label in query.split("."))
        if not (known_bad or long_query or long_labels):
            return None
        reason = "known-bad domain indicator" if known_bad else ("long query length" if long_query else "long subdomain label")
        return make_match(
            self, event, severity="HIGH" if known_bad else "MEDIUM",
            technique_id="T1071.004", technique_name="Application Layer Protocol: DNS",
            title=f"Suspicious DNS query: {query[:80]}",
            description=f"DNS query '{query[:120]}' flagged: {reason}.",
            ev=[evidence("domain", query, reason),
                evidence("process_name", event.get("process_name"), "resolver process"),
                evidence("source_ip", event.get("source_ip"), "querying host/IP")],
        )


class RemotePortScanRule(DetectionRule):
    rule_id = "MULTIPLE_REMOTE_PORTS"
    rule_name = "Rapid connections to multiple ports/hosts"
    description = "Detects scanning behavior across a session (stateful)."

    def __init__(self) -> None:
        self._seen: dict[str, set[str]] = {}

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "NETWORK_CONNECTION":
            return None
        dst = event.get("destination_ip") or ""
        if not dst or _is_private(dst):
            return None
        src = event.get("source_ip") or event.get("host") or "unknown"
        bucket = self._seen.setdefault(str(src).lower(), set())
        bucket.add(dst)
        if len(bucket) < 8:
            return None
        return make_match(
            self, event, severity="MEDIUM", technique_id="T1046",
            technique_name="Network Service Discovery",
            title=f"{len(bucket)} distinct external destinations from {src}",
            description=f"Source {src} contacted {len(bucket)} distinct external addresses - scanning or beacon fan-out.",
            ev=[evidence("source_ip", src, "scanning source"),
                evidence("destination_count", len(bucket), "distinct destinations")],
        )


NETWORK_RULES: list[DetectionRule] = [
    UnusualOutboundConnectionRule(),
    DnsTunnelingRule(),
    RemotePortScanRule(),
]
