# Changelog

All notable changes to ACR (Attack Chain Reconstruction Engine).
Format: [Keep a Changelog](https://keepachangelog.com/). Every entry below was
shipped, tested and pushed to `main` in its own commit.

## [Unreleased]

Nothing pending.

## [2026-10-03]

### Added — frontend dashboard (this session)

- **Kill-chain UI** (`d42df75`): shared `KillChainStrip` component driven by
  `/api/config.kill_chain`; per-chain coverage strip on the Chains list,
  coverage bar under the Investigate workspace header, `KCn` stage chip on
  every ATT&CK tactic column plus a stage chip in the technique detail panel.
  Stage names/numbers always come from the backend mapping
  (`backend/app/core/killchain.py`) — nothing is guessed client-side.
- **Overview dashboard** (`8773fe2`, route `/overview`): stat tiles from
  `/api/stats`, live pipeline strip with provenance (last ingest dataset
  label / chains rebuilt), kill-chain coverage bar from MITRE coverage,
  evaluation snapshot from the stage-comparison API, data catalog snapshot
  with the honest "no ground truth" note, highest-risk chain links.
- **Light theme** (`64dba66`): dark remains default; `[data-theme]` token
  remap, pre-paint script, LIGHT/DARK toggle in the nav, persisted in
  `localStorage`.
- **Global toasts** (`126255a`): `ToastProvider`/`useToast`, wired into
  analyst feedback, dataset runs, evaluation runs, scenario generate/reset
  and file ingest. Inline notices kept; toasts add global visibility.
- **Command palette** (`f5f3f2e`): `Ctrl/Cmd+K`, fuzzy filter over all 9
  routes + theme toggle + landing action, arrow/enter/esc keyboard flow,
  `⌘K` trigger button in the nav.
- **Loading skeletons** (`b39c709`): pulse placeholders for Overview and
  Evaluate; other pages already had loaders.
- **Data page** (`5924fdd`, `/data`): dataset catalog with provenance chips
  (synthetic vs real), ground-truth badges, plain-text origin URLs (never
  opened by the app), RUN DATASET with honest result panel and skip reasons,
  run history table.

### Added — backend (earlier commits)

- Kill-chain mapping as single source of truth (`core/killchain.py`),
  exposed via `/api/config.kill_chain`, surfaced on chain/technique schemas.
- IOC import (`POST /api/ioc/import`) with validation + normalization.
- Dataset catalog: 4 adapters (scenario, OTRF, EVTX CSV, Splunk), catalog
  JSON with labels/provenance/sha256, dataset endpoints
  (`GET /api/datasets`, run + history endpoints), `dataset_runs` table.
- `scripts/fetch_datasets.py`: download -> sha256-verify -> convert tool
  with `--check` mode (fails loudly on hash mismatch).

## Test status (2026-10-03)

- `python -m pytest backend/tests -q` — 128 passed (exit 0)
- `python -m ruff check backend` — clean
- `npm run build` — clean; `npm run lint` — 2 pre-existing warnings only
  (`BootSequence.tsx`, `Events.tsx`, untouched by this work)
- Headless-browser smoke on every route: 0 console errors, 0 failed requests
