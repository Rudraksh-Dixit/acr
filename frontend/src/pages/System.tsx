import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import { uploadEventFile } from '../api/events'
import type { IngestReportOut } from '../api/types'
import { ErrorState, StatusDot, TechLabel } from '../components/ui/primitives'
import { useConfig, useHealth, usePipeline, useStats } from '../hooks/systemQueries'

function Card({ title, children, right }: { title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="rounded-sm border border-line bg-panel">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <TechLabel>{title}</TechLabel>
        {right}
      </div>
      <div className="px-4 py-4">{children}</div>
    </section>
  )
}

function IssueRow({ issue }: { issue: NonNullable<IngestReportOut['issues']>[number] }) {
  const tone = issue.scope === 'error' || issue.scope === 'record' ? 'var(--color-warm)' : 'var(--color-fg-faint)'
  return (
    <li className="flex items-start gap-3 border-b border-line/60 py-2 last:border-0">
      <span className="mt-1 inline-block h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: tone }} />
      <span className="w-16 shrink-0 text-[10px] tracking-[0.1em] text-fg-faint uppercase">{issue.scope}</span>
      <span className="min-w-0 flex-1">
        {issue.field ? <span className="mr-2 text-fg-muted mono">{issue.field}:</span> : null}
        <span className="text-fg-muted">{issue.message}</span>
      </span>
      {issue.index != null ? <span className="text-[10px] text-fg-faint mono">#{issue.index}</span> : null}
    </li>
  )
}

export default function SystemPage() {
  const health = useHealth()
  const stats = useStats()
  const config = useConfig()
  const pipeline = usePipeline()
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [report, setReport] = useState<IngestReportOut | null>(null)
  const [stage, setStage] = useState(-1)

  const upload = useMutation({
    mutationFn: (file: File) => uploadEventFile(file, { reconstruct: true }),
    onMutate: () => {
      setReport(null)
      setStage(0)
      return {}
    },
    onSuccess: (data) => {
      setStage(3)
      setReport(data)
      void qc.invalidateQueries({ queryKey: ['chains'] })
      void qc.invalidateQueries({ queryKey: ['events'] })
      void qc.invalidateQueries({ queryKey: ['stats'] })
      void qc.invalidateQueries({ queryKey: ['global-graph'] })
      void qc.invalidateQueries({ queryKey: ['pipeline'] })
    },
    onError: () => setStage(-1),
  })

  if (health.isError && !health.data) {
    return (
      <ErrorState
        title="ACR ENGINE OFFLINE"
        message={health.error instanceof Error ? health.error.message : undefined}
        onRetry={() => void health.refetch()}
      />
    )
  }

  const weights = Object.entries(config.data?.weights ?? {}).sort((a, b) => b[1] - a[1])
  const maxWeight = Math.max(1, ...weights.map(([, w]) => w))
  const uploadStages = ['FILE RECEIVED', 'VALIDATING', 'NORMALIZING', 'INGESTED']

  return (
    <div className="mx-auto max-w-[1500px] px-8 py-10">
      <header className="mb-8 flex items-end justify-between">
        <div>
          <TechLabel>Engine status, configuration and ingestion</TechLabel>
          <h1 className="display mt-2 text-5xl tracking-tight">SYSTEM</h1>
        </div>
        <div className="flex items-center gap-3 rounded-sm border border-line px-3 py-2">
          <StatusDot tone={health.data?.status === 'ok' ? 'ok' : 'down'} pulse={!!health.isError} />
          <span className="text-[11px] tracking-[0.14em] text-fg-muted">
            {health.data?.status === 'ok' ? 'API ONLINE' : health.isError ? 'API OFFLINE' : 'CONNECTING'}
          </span>
          <span className="text-[11px] text-fg-faint mono">{health.data?.version ?? ''}</span>
        </div>
      </header>

      <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="API status">
          <dl className="space-y-2.5 text-[12px]">
            {[
              ['Application', health.data?.app],
              ['Version', health.data?.version],
              ['Database', health.data ? `${health.data.database} (${health.data.database_ok ? 'ok' : 'FAILING'})` : undefined],
              ['Server time', health.data?.time],
            ].map(([k, v]) => (
              <div key={String(k)} className="flex items-baseline justify-between gap-4 border-b border-line/50 pb-2 last:border-0">
                <dt className="text-fg-faint">{k}</dt>
                <dd className="truncate text-right text-fg-muted mono">{v ?? '\u2014\u2014'}</dd>
              </div>
            ))}
          </dl>
        </Card>

        <Card title="Store counts">
          <div className="grid grid-cols-4 gap-3">
            {Object.entries(stats.data?.counts ?? {}).map(([k, v]) => (
              <div key={k}>
                <div className="display text-2xl leading-none">{v}</div>
                <div className="mt-1 text-[9px] tracking-[0.1em] text-fg-faint uppercase">{k.replace(/_/g, ' ')}</div>
              </div>
            ))}
          </div>
          <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-3">
            {Object.entries(stats.data?.events_by_severity ?? {}).map(([sev, n]) => (
              <span key={sev} className="flex items-center gap-1.5 text-[10px] text-fg-muted">
                <span
                  className="inline-block h-1.5 w-1.5 rounded-full"
                  style={{
                    background:
                      sev === 'HIGH' || sev === 'CRITICAL'
                        ? 'var(--color-risk)'
                        : sev === 'MEDIUM'
                          ? 'var(--color-warm)'
                          : 'var(--color-normal)',
                  }}
                />
                {sev} <span className="text-fg mono">{n}</span>
              </span>
            ))}
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {Object.entries(stats.data?.chains_by_risk_level ?? {}).map(([lvl, n]) => (
              <span key={lvl} className="text-[10px] text-fg-faint">
                {lvl} <span className="text-fg-muted mono">{n}</span>
              </span>
            ))}
          </div>
        </Card>

        <Card title="Pipeline">
          <ol className="space-y-2.5">
            {(pipeline.data?.stages ?? []).map((s, i) => (
              <li key={s.stage} className="flex items-center gap-3">
                <span className="w-4 text-[10px] text-fg-faint mono">{i + 1}</span>
                <span className="w-32 text-[11px] tracking-[0.1em] text-fg-muted uppercase">{s.stage}</span>
                <span className="min-w-0 flex-1 truncate text-[11px] text-fg-faint">{s.description}</span>
                <span className="text-[11px] text-fg mono">{s.count ?? '\u2014\u2014'}</span>
              </li>
            ))}
          </ol>
        </Card>
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Correlation weights (sum = 100)" right={<TechLabel>engine: {config.data?.engine ?? '\u2026'}</TechLabel>}>
          <ul className="space-y-2">
            {weights.map(([name, w]) => (
              <li key={name} className="grid grid-cols-[180px_1fr_40px] items-center gap-3">
                <span className="truncate text-[11px] text-fg-muted mono">{name}</span>
                <span className="h-2 overflow-hidden rounded-full bg-white/6">
                  <span
                    className="block h-full rounded-full bg-white/50"
                    style={{ width: `${(w / maxWeight) * 100}%` }}
                  />
                </span>
                <span className="text-right text-[11px] text-fg mono">{w}</span>
              </li>
            ))}
          </ul>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 border-t border-line pt-3 text-[11px] text-fg-faint">
            <span>min edge score <span className="text-fg-muted mono">{config.data?.min_edge_score}</span></span>
            <span>attack confidence <span className="text-fg-muted mono">{config.data?.attack_confidence_threshold}</span></span>
            <span>attack risk <span className="text-fg-muted mono">{config.data?.attack_risk_threshold}</span></span>
            <span>windows <span className="text-fg-muted mono">
              {Object.entries(config.data?.time_windows ?? {}).map(([k, v]) => `${k} ${v}s`).join(' / ')}
            </span></span>
          </div>
        </Card>

        <Card title="Ingestion">
          <div className="flex flex-wrap items-center gap-3">
            <input
              ref={fileRef}
              type="file"
              accept=".json,.csv,application/json,text/csv"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0]
                if (f) upload.mutate(f)
                e.target.value = ''
              }}
            />
            <button
              onClick={() => fileRef.current?.click()}
              disabled={upload.isPending}
              className="rounded-sm border border-fg/60 px-4 py-2 text-[11px] tracking-[0.16em] text-fg hover:bg-white/8 disabled:opacity-40"
            >
              UPLOAD JSON / CSV
            </button>
            <span className="text-[11px] text-fg-faint">
              max {(Number(config.data?.max_upload_bytes ?? 0) / 1_000_000).toFixed(1)} MB · runs detection + reconstruction
            </span>
          </div>

          <ol className="mt-4 flex items-center gap-2">
            {uploadStages.map((label, i) => (
              <li key={label} className="flex items-center gap-2">
                {i > 0 ? <span className="text-fg-faint">{'\u2192'}</span> : null}
                <span
                  className="rounded-sm border px-2 py-1 text-[10px] tracking-[0.12em]"
                  style={{
                    color: stage >= i ? 'var(--color-fg)' : 'var(--color-fg-faint)',
                    borderColor: stage >= i ? 'var(--color-line-strong)' : 'var(--color-line)',
                    opacity: stage >= 0 ? 1 : 0.45,
                  }}
                >
                  {label}
                </span>
              </li>
            ))}
          </ol>

          {upload.isError ? (
            <div className="mt-4 rounded-sm border px-3 py-2 text-[11px] text-risk mono" style={{ borderColor: 'var(--color-risk-deep)' }}>
              UPLOAD FAILED — {upload.error instanceof Error ? upload.error.message : 'unknown error'}
            </div>
          ) : null}

          {report ? (
            <div className="mt-5 border-t border-line pt-4">
              <div className="grid grid-cols-6 gap-3">
                {[
                  ['RECEIVED', report.received],
                  ['STORED', report.stored],
                  ['DUPES', report.duplicates],
                  ['SKIPPED', report.skipped],
                  ['DETECTIONS', report.detections],
                  ['EV/S', Math.round(report.events_per_second ?? 0)],
                ].map(([k, v]) => (
                  <div key={String(k)}>
                    <div className="display text-lg leading-none">{String(v)}</div>
                    <TechLabel className="!text-[9px]">{String(k)}</TechLabel>
                  </div>
                ))}
              </div>

              {report.reconstruction ? (
                <div className="mt-3 text-[11px] text-fg-muted">
                  reconstruction:{' '}
                  <span className="mono text-fg">
                    {String((report.reconstruction as Record<string, unknown>).chains ?? '\u2014')} chains
                  </span>
                </div>
              ) : null}

              {report.issues.length > 0 ? (
                <div className="mt-4">
                  <TechLabel className="mb-1 block">Validation / normalization issues ({report.issue_count})</TechLabel>
                  <ul className="max-h-48 overflow-y-auto">
                    {report.issues.map((issue, i) => (
                      <IssueRow key={i} issue={issue} />
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="mt-4 text-[11px] text-fg-faint">No issues — every record normalized cleanly.</div>
              )}
            </div>
          ) : null}
        </Card>
      </div>
    </div>
  )
}
