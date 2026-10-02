# ACR demo walkthrough

End-to-end demo of the frontend. Every number shown during the demo comes
from the live API — nothing on screen is fabricated. Store counts depend on
what has been ingested; the examples below assume the bundled demo store.

## Start

```bat
D:\Start-ACR.bat        :: backend :8000 + frontend :5173, demo DB preloaded
```

Open http://localhost:5173 — boot sequence runs once per browser session,
then lands on `/investigate`. Nav: OVERVIEW · INVESTIGATE · CHAINS · EVENTS ·
DATA · ATT&CK · SIMULATE (+ EVALUATE, SYSTEM on the right).

## 1. Overview (`/overview`)

- **Stat tiles** — events / detections / chains / entities / techniques from
  `/api/stats`.
- **Pipeline strip** — 6 stages with live counts; provenance line shows the
  last ingest dataset label or "chains rebuilt".
- **Kill-chain bar** — 7 Lockheed stages from `/api/config.kill_chain`;
  per-stage bars count observed MITRE techniques mapped to that stage.
  Unobserved stages show 0 (never invented).
- **Evaluation snapshot** — technique F1 by stage + chain accuracy / event
  latency / ingest throughput deltas from the stage-comparison API.
- **Data snapshot + highest-risk chains** — catalog labels (synthetic vs
  real), honest "metrics not computed (no ground truth)" note when relevant;
  chain rows link into `/investigate`.

## 2. Data (`/data`) — dataset catalog

- 4 catalog entries with provenance: **synthetic** (ACR scenarios) vs
  **real** (OTRF Security Datasets, EVTX-Attack-Samples, Splunk Attack Data).
- Ground-truth badges, origin URLs rendered as **plain text** (the app never
  opens them), sha256 provenance in the data files.
- **RUN DATASET** on a real source (e.g. OTRF): result panel reports
  received / stored / skipped with per-reason issue list, detections and
  chains. Evaluation block states either real metrics (ground-truth data) or
  "metrics not computed (no ground truth)" — no invented precision/recall.
- Run history table below shows every run with its evaluation note.

## 3. Simulate (`/simulate`)

- GENERATE on any scenario: animated pipeline stages, then honest counts
  (events stored, detections, chains, attack chains).
- RESET (double-confirm) clears the store — overview will then legitimately
  show zeros.

## 4. Investigate (`/investigate/:chainId`)

- **Kill-chain bar** under the header shows which of the 7 stages the active
  chain covers (highlighted = covered, from `kill_chain_stages`).
- Views: ATTACK GRAPH / PROCESS TREE / NETWORK; OBSERVED vs INFERRED legend.
- **REPLAY ATTACK** — scrubs the timeline, revealing events progressively
  (timeline dots support manual scrubbing too).
- Right rail: signals (confidence, risk, duration), tactics/techniques,
  ATT&CK sequence, "WHY THIS CHAIN" weighted links, RISK FACTORS — all from
  the API's explanation fields.
- **Analyst actions**: comment box + CONFIRM / DISMISS / MARK BENIGN /
  INVESTIGATE; feedback history below. Success shows a toast
  (`ACR-0003 → CONFIRMED`); status chip updates immediately.

## 5. Chains (`/chains`)

- Filter ALL/ATTACK/BENIGN, sort RISK/CONFIDENCE/RECENT.
- Each row shows tactics path, hosts/users/events, and a **kill-chain strip**
  (7 stage boxes, highlighted = covered by that chain).

## 6. ATT&CK (`/attack`)

- Tactic columns with per-tactic **KCn chip** (kill-chain stage from the
  backend mapping) and observed/not-observed counts.
- Technique detail panel: description, detection hint, observed status,
  kill-chain stage ("7 · Actions on Objectives"), associated chains.

## 7. Evaluate (`/evaluate`)

- RUN EVALUATION → toast + metrics for the three pipeline stages
  (technique-level and event-level F1/precision/recall vs scenario ground
  truth) and delta block (chain accuracy, latency, throughput).

## 8. Theme & palette

- LIGHT/DARK toggle in the nav (persisted; dark default).
- `Ctrl+K` / `Cmd+K` (or the `⌘K` button): command palette — type to filter,
  arrows to move, Enter to run (navigate or toggle theme), Esc to close.

## Screenshot instructions (for docs/README figures)

Committed screenshots live in [`docs/screenshots/`](screenshots) and are
embedded in the README (regenerate with the snippet below if the UI changes).
Headless Chrome (present on this machine) — one script per shot:

```js
// run inside frontend/ with puppeteer-core available
const p = await puppeteer.launch({
  executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  headless: 'new', args: ['--no-sandbox'],
})
const page = await p.newPage()
await page.setViewport({ width: 1600, height: 950 })
// skip boot overlay for clean shots
await page.evaluateOnNewDocument(() => sessionStorage.setItem('acr:booted', '1'))
await page.goto('http://localhost:5173/overview', { waitUntil: 'networkidle2' })
await page.screenshot({ path: 'overview.png' })
await p.close()
```

Routes worth capturing: `/overview`, `/chains`, `/investigate/ACR-0001`,
`/attack` (select T1003.001), `/data`, `/evaluate`. Delete throwaway
`.cjs` scripts after use; screenshots are review artifacts, not repo files.

## Honesty rules observed during the demo

- Every displayed metric traces to an API response; no placeholder numbers.
- Datasets are labelled synthetic or real (source name) everywhere.
- Real data without ground truth reports detections/chains/skip reasons —
  precision/recall is explicitly "not computed".
- Origin URLs render as text only; the app never fetches or opens them.
- Unknown ATT&CK→kill-chain mappings return null; the UI hides the field
  rather than guessing.
