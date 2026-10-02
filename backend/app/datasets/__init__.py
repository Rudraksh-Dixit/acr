"""Dataset catalog + adapter registry.

``data/datasets/catalog.json`` is the single index of datasets. Every entry
carries its provenance label (``synthetic`` / ``real (source name)``), the
adapter that can read it, and where the file lives (bundled or fetched).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from app.core.config import BASE_DIR, settings
from app.datasets import evtx, otrf, scenario, splunk
from app.datasets.base import AdapterLoad, AdapterResult, DatasetError, DatasetMissingError

ADAPTERS: dict[str, AdapterLoad] = {
    "scenario": scenario.load,
    "otrf_json": otrf.load,
    "evtx_csv_json": evtx.load,
    "splunk_log": splunk.load,
}

CATALOG_RELATIVE = Path("data") / "datasets" / "catalog.json"


def catalog_path() -> Path:
    """Catalog location: ACR_DATA_DIR when set, else <project>/data."""
    override = Path(settings.data_dir) / "datasets" / "catalog.json"
    if override.exists() or Path(settings.data_dir).as_posix() != (BASE_DIR / "data").as_posix():
        return override
    return BASE_DIR / CATALOG_RELATIVE


def read_catalog() -> dict[str, Any]:
    path = catalog_path()
    if not path.exists():
        raise DatasetMissingError(
            f"dataset catalog not found: {path}",
            hint="restore data/datasets/catalog.json from the repository",
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise DatasetError(f"dataset catalog is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("datasets"), list):
        raise DatasetError("dataset catalog must be an object with a 'datasets' list")
    return payload


def resolve_path(entry: dict[str, Any]) -> Optional[Path]:
    """Catalog paths are project-root relative (e.g. data/datasets/real/x.json)."""
    rel = entry.get("path")
    if not rel:
        return None
    candidate = Path(rel)
    if candidate.is_absolute():
        return candidate
    return BASE_DIR / candidate


def dataset_entry(dataset_id: str) -> Optional[dict[str, Any]]:
    for entry in read_catalog().get("datasets", []):
        if entry.get("id") == dataset_id:
            return entry
    return None


def availability(entry: dict[str, Any]) -> dict[str, Any]:
    """Whether a dataset's file is present locally right now."""
    if entry.get("adapter") == "scenario":
        return {"available": True, "path": None, "fetch_hint": None}
    path = resolve_path(entry)
    present = bool(path and path.exists())
    return {
        "available": present,
        "path": str(path) if path else None,
        "fetch_hint": None if present else "python scripts/fetch_datasets.py",
    }


def load_dataset(entry: dict[str, Any], *, seed: int = 42) -> AdapterResult:
    """Dispatch to the adapter named by the catalog entry."""
    adapter_name = entry.get("adapter")
    if adapter_name not in ADAPTERS:
        raise DatasetError(
            f"unknown adapter '{adapter_name}' for dataset '{entry.get('id')}'",
            hint=f"known adapters: {', '.join(sorted(ADAPTERS))}",
        )
    load = ADAPTERS[adapter_name]
    if adapter_name == "scenario":
        result = load(None, entry, seed=seed)  # type: ignore[call-arg]
    else:
        result = load(resolve_path(entry), entry)
    # provenance is attached to every record so it survives normalization
    for record in result.records:
        meta = record.setdefault("metadata", {})
        if isinstance(meta, dict):
            meta.setdefault("dataset_label", entry.get("label"))
            meta.setdefault("dataset_id", entry.get("id"))
            meta.setdefault("dataset_kind", entry.get("kind"))
    result.meta.update({
        "dataset_id": entry.get("id"),
        "label": entry.get("label"),
        "kind": entry.get("kind"),
        "source_name": entry.get("source_name"),
        "ground_truth": bool(entry.get("ground_truth")),
        "adapter": adapter_name,
    })
    return result


__all__ = [
    "ADAPTERS",
    "AdapterResult",
    "DatasetError",
    "DatasetMissingError",
    "availability",
    "catalog_path",
    "dataset_entry",
    "load_dataset",
    "read_catalog",
    "resolve_path",
]
