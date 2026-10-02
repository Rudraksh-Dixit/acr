"""Authentication-focused detection rules (brute force, valid accounts, privileges)."""
from __future__ import annotations

from typing import Any, Optional

from app.detection.base import (
    DetectionRule,
    RuleContext,
    RuleMatch,
    evidence,
    make_match,
)

ADMIN_MARKERS = ("admin", "administrator", "root", "svc_", "service", "domain admin", "enterprise admin")


class BruteForceRule(DetectionRule):
    rule_id = "AUTH_BRUTE_FORCE"
    rule_name = "Repeated failed authentication"
    description = "Multiple failed logins from one source against one account within the configured window."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "LOGIN_ATTEMPT":
            return None
        user = event.get("user") or "unknown"
        source = event.get("source_ip") or event.get("host") or "unknown"
        key = (str(source).lower(), str(user).lower())
        failures = ctx.record_login_failure(key, event.get("timestamp"))
        threshold = ctx.settings.brute_force_failures
        if len(failures) < threshold:
            return None
        return make_match(
            self,
            event,
            severity="HIGH",
            technique_id="T1110.001",
            technique_name="Brute Force: Password Guessing",
            title=f"{len(failures)} failed logins for '{user}' from {source}",
            description=(
                f"{len(failures)} failed authentication attempts originated from {source} "
                f"against account '{user}' within {ctx.settings.brute_force_window}s."
            ),
            ev=[
                evidence("user", user, "targeted account"),
                evidence("source_ip", source, "attacker source"),
                evidence("failure_count", len(failures), f"threshold {threshold}"),
                evidence("window_seconds", ctx.settings.brute_force_window, "correlation window"),
            ],
            related=[event.get("event_id")] if event.get("event_id") else [],
        )


class ValidAccountAfterFailuresRule(DetectionRule):
    rule_id = "AUTH_SUCCESS_AFTER_FAILURES"
    rule_name = "Successful login after repeated failures"
    description = "A successful login that immediately follows repeated failures suggests credential guessing succeeded."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "LOGIN_SUCCESS":
            return None
        user = event.get("user") or "unknown"
        source = event.get("source_ip") or event.get("host") or "unknown"
        key = (str(source).lower(), str(user).lower())
        count = ctx.failure_count(key)
        ctx.login_failures.pop(key, None)  # a success resets the guessing window
        if count < ctx.settings.brute_force_failures:
            return None
        return make_match(
            self,
            event,
            severity="CRITICAL",
            technique_id="T1078",
            technique_name="Valid Accounts",
            title=f"Successful login for '{user}' after {count} failures",
            description=(
                f"Account '{user}' authenticated successfully from {source} after {count} "
                "failed attempts - a classic password-guessing success pattern."
            ),
            ev=[
                evidence("user", user, "account that finally succeeded"),
                evidence("source_ip", source, "source of the successful auth"),
                evidence("prior_failures", count, "preceding failed attempts"),
            ],
        )


class PrivilegedLogonRule(DetectionRule):
    rule_id = "PRIVILEGED_LOGON"
    rule_name = "Privilege assignment / escalation indicator"
    description = "Special privileges assigned to a logon or membership escalation."

    def evaluate(self, event: dict[str, Any], ctx: RuleContext) -> Optional[RuleMatch]:
        if event.get("event_type") != "PRIVILEGE_CHANGE":
            return None
        user = event.get("user") or "unknown"
        meta = event.get("metadata") or {}
        meta_text = " ".join(str(v).lower() for v in meta.values()) if isinstance(meta, dict) else ""
        cmd = (event.get("command_line") or "").lower()
        uac_markers = ("fodhelper", "compmgmt", "eventvwr", "sdclt", "cmstp", "sdclt.exe", "uaclcrl", "consent.exe")
        is_uac = any(m in meta_text or m in cmd for m in uac_markers)
        if is_uac:
            return make_match(
                self, event, severity="HIGH", technique_id="T1548.002",
                technique_name="Abuse Elevation Control Mechanism: Bypass User Account Control",
                title="UAC bypass indicator observed",
                description=f"Privilege-related activity on {event.get('host')} includes a known UAC bypass pattern.",
                ev=[evidence("user", user, "account elevating"), evidence("host", event.get("host"), "affected host"),
                    evidence("command_line", event.get("command_line"), "UAC bypass marker")],
            )
        is_admin = any(marker in str(user) for marker in ADMIN_MARKERS) or "sebackup" in meta_text or "sedebug" in meta_text
        severity = "HIGH" if is_admin else "MEDIUM"
        return make_match(
            self, event, severity=severity, technique_id="T1078",
            technique_name="Valid Accounts",
            title=f"Privileged logon/session for '{user}'",
            description=(
                f"Special privileges were assigned to '{user}' on {event.get('host')}. "
                "Privileged sessions are required for most post-exploitation activity."
            ),
            ev=[evidence("user", user, "account receiving privileges"),
                evidence("host", event.get("host"), "affected host"),
                evidence("metadata", meta, "privilege details")],
        )


AUTH_RULES: list[DetectionRule] = [BruteForceRule(), ValidAccountAfterFailuresRule(), PrivilegedLogonRule()]
