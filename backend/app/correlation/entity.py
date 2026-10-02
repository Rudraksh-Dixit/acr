"""Entity-correlation signal: which entities do two events share?"""
from __future__ import annotations

from typing import Any, Optional



def _same(a: dict[str, Any], b: dict[str, Any], key: str) -> Optional[str]:
    va, vb = a.get(key), b.get(key)
    if not va or not vb:
        return None
    if str(va).lower() == str(vb).lower():
        return str(va).lower()
    return None


def shared_entities(a: dict[str, Any], b: dict[str, Any]) -> dict[str, str]:
    """Return {signal_name: shared_value} for every entity signal that fires."""
    shared: dict[str, str] = {}
    for signal_key, field in (
        ("same_host", "host"),
        ("same_user", "user"),
        ("same_source_ip", "source_ip"),
        ("same_destination_ip", "destination_ip"),
        ("shared_domain", "domain"),
    ):
        value = _same(a, b, field)
        if value:
            shared[signal_key] = value

    fa, fb = a.get("file_path"), b.get("file_path")
    if fa and fb and str(fa).lower() == str(fb).lower():
        shared["shared_file"] = str(fa).lower()
    return shared
