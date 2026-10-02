"""`python -m acr` entrypoint.

Adds backend/ to sys.path so the `app` package resolves, then delegates to
app.cli. Run from the project root (D:\\OpenCode\\acr).
"""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
