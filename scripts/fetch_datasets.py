#!/usr/bin/env python3
"""Fetch and convert external datasets listed in data/datasets/catalog.json.

For every catalog entry with an ``origin`` block this script:
  1. downloads ``origin.url`` to ``origin.artifact`` (unless already present),
  2. verifies the download against ``origin.sha256`` (mismatch => discard),
  3. converts it into the bundled file at the entry's ``path`` so the app can
     load it offline through the matching adapter.

No dataset content is ever executed: files are only downloaded, hashed,
unzipped and re-serialised. Run with ``--check`` to verify local files
without network access. Exit code is non-zero on any failure.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "datasets" / "catalog.json"

# --- conversion parameters (mirrors the bundled samples shipped in the repo)
EVTX_MAPPED_EVENT_IDS = {
    "1", "3", "7", "11", "12", "13", "22", "4624", "4625", "4672",
    "4688", "4697", "4698", "7045", "5156", "5158", "4648", "4663",
}
EVTX_ROW_CAP = 400
EVTX_PER_FILE_CAP = 60
USER_AGENT = "acr-fetch-datasets/1.0"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path) -> None:
    """Download plain bytes; never executes or opens the content."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        data = response.read()
    tmp = dest.with_suffix(dest.suffix + ".part")
    tmp.write_bytes(data)
    tmp.replace(dest)


def convert_otrf(artifact: Path) -> list[dict[str, Any]]:
    with zipfile.ZipFile(artifact) as bundle:
        jsonl_names = [n for n in bundle.namelist() if n.endswith(".json") or n.endswith(".jsonl")]
        if not jsonl_names:
            raise ValueError("no JSON/JSONL file inside the OTRF zip")
        raw = bundle.read(jsonl_names[0]).decode("utf-8", "replace")
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def convert_evtx(artifact: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_files: dict[str, int] = {}
    with artifact.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            event_id = row.get("EventID", "")
            if event_id not in EVTX_MAPPED_EVENT_IDS:
                continue
            useful = (
                (row.get("CommandLine") or "").strip() not in ("", "-")
                or (row.get("ProcessName") or "").strip() not in ("", "-")
                or (row.get("IpAddress") or "").strip() not in ("", "-")
                or (row.get("DestAddress") or "").strip() not in ("", "-")
                or event_id in {"11", "13", "4698", "7045", "4697"}
            )
            if not useful:
                continue
            file_name = row.get("EVTX_FileName", "")
            if seen_files.get(file_name, 0) >= EVTX_PER_FILE_CAP:
                continue
            seen_files[file_name] = seen_files.get(file_name, 0) + 1
            rows.append({k: v for k, v in row.items() if k != "" and v not in ("", "-")})
            if len(rows) >= EVTX_ROW_CAP:
                break
    if not rows:
        raise ValueError("no usable rows found in the EVTX CSV")
    return rows


def convert_passthrough(artifact: Path) -> bytes:
    return artifact.read_bytes()


CONVERTERS = {
    "otrf_json": ("json", convert_otrf),
    "evtx_csv_json": ("json", convert_evtx),
    "splunk_log": ("bytes", convert_passthrough),
}


def process(entry: dict[str, Any], *, check_only: bool, force: bool) -> tuple[bool, str]:
    """Returns (ok, message) for one catalog entry."""
    origin = entry.get("origin")
    if not origin:
        return True, f"skip  {entry['id']}: bundled/generated (no origin)"
    artifact = ROOT / origin["artifact"]
    target = ROOT / entry["path"]
    expected = origin.get("sha256", "")

    # 1. artifact (download once, verify always)
    if artifact.exists() and expected and sha256_file(artifact) == expected:
        action = "reuse"
    elif check_only:
        return False, f"FAIL  {entry['id']}: missing/stale artifact {origin['artifact']} (run without --check)"
    else:
        if artifact.exists() and not force:
            print(f"      {entry['id']}: stale artifact present, re-downloading")
        download(origin["url"], artifact)
        actual = sha256_file(artifact)
        if expected and actual != expected:
            artifact.unlink(missing_ok=True)
            return False, f"FAIL  {entry['id']}: sha256 mismatch (expected {expected[:12]}..., got {actual[:12]}...)"
        action = "fetch"

    # 2. conversion to the bundled path
    kind = entry.get("adapter")
    if kind not in CONVERTERS:
        return False, f"FAIL  {entry['id']}: no converter for adapter '{kind}'"
    if check_only:
        if not target.exists():
            return False, f"FAIL  {entry['id']}: bundled file missing {entry['path']}"
        return True, f"ok    {entry['id']}: artifact + bundled file verified"
    if force or action == "fetch" or not target.exists():
        mode, converter = CONVERTERS[kind]
        if mode == "json":
            payload = json.dumps(converter(artifact), indent=1)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(payload, encoding="utf-8")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(converter(artifact))
        size = target.stat().st_size
        return True, f"ok    {entry['id']}: {action} + convert -> {entry['path']} ({size} bytes)"
    return True, f"ok    {entry['id']}: {action}, bundled file unchanged"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify local files only, no downloads")
    parser.add_argument("--force", action="store_true", help="re-download and re-convert everything")
    parser.add_argument("--dataset", help="process a single dataset id")
    args = parser.parse_args()

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    entries = catalog.get("datasets", [])
    if args.dataset:
        entries = [e for e in entries if e.get("id") == args.dataset]
        if not entries:
            print(f"FAIL  dataset '{args.dataset}' not in {CATALOG}")
            return 1

    failures = 0
    for entry in entries:
        try:
            ok, message = process(entry, check_only=args.check, force=args.force)
        except Exception as exc:  # noqa: BLE001 - report per dataset, keep going
            ok, message = False, f"FAIL  {entry.get('id')}: {type(exc).__name__}: {exc}"
        print(message)
        if not ok:
            failures += 1
    print(f"\n{'all datasets OK' if failures == 0 else f'{failures} dataset(s) failed'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
