import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { runEvaluation } from '../api/evaluation'
import { ErrorState, TechLabel } from '../components/ui/primitives'
import { useEvaluationRuns, useStageComparison } from '../hooks/queries'
import { useToast } from '../lib/toast'

type StageKey = 'raw_detection' | 'correlation' | 'reconstruction'

function asNum(v: unknown): number | undefined {
  return typeof v === 'number' && !Number.isNaN(v) ? v : undefined
}

function asF1(v: unknown): number | null {
  return typeof v === 'number' ? v : null
}

const STAGES: Array<{ key: StageKey; label: string; sub: string }> = [
  { key: 'raw_detection', label: 'RAW', sub: 'detection rules only' },
  { key: 'correlation', label: 'CORRELATED', sub: 'multi-signal clusters' },
  { key: 'reconstruction', label: 'RECONSTRUCTED', sub: 'seeded attack chains' },
]

function f1(v: number | null | undefined): string {
  return v == null ? '\u2014\u2014' : v.toFixed(3)
}

function deltaText(v: number | null | undefined, digits = 3): string {
  if (v == null) return '\u2014\u2014'
  const sign = v > 0 ? '+' : ''
  return sign + v.toFixed(digits)
}

function MetricBlock({
  title,
  rows,
  showFpr = false,
}: {
  title: string
  rows: Record<string, Record<string, unknown>> | undefined
  showFpr?: boolean
}) {
  if (!rows) return null
  const stageKeys: StageKey[] = ['raw_detection', 'correlation', 'reconstruction']
  return (
    <div className="border-b border-line py-4 last:border-0">
      <TechLabel className="mb-2 block">{title}</TechLabel>
      <div className="grid grid-cols-[200px_repeat(3,minmax(0,1fr))] gap-4 border-b border-line/60 pb-2 text-[10px] tracking-[0.12em] text-fg-faint uppercase">
        <span>Metric</span>
        {stageKeys.map((k) => (
          <span key={k}>{STAGES.find((s) => s.key === k)?.label}</span>
        ))}
      </div>
      {(['precision', 'recall', 'f1'] as const).map((metric) => (
        <div
          key={metric}
          className="grid grid-cols-[200px_repeat(3,minmax(0,1fr))] items-center gap-4 border-b border-line/40 py-2 last:border-0"
        >
          <TechLabel>{metric}</TechLabel>
          {stageKeys.map((k, idx) => {
            const v = asF1(rows[k]?.[metric])
            const prev = idx > 0 ? asF1(rows[stageKeys[idx - 1]]?.[metric]) : null
            const up = v != null && prev != null && v > prev
            const down = v != null && prev != null && v < prev
            return (
              <span key={k} className="flex items-baseline gap-2">
                <span className="text-[13px] text-fg mono">{f1(v)}</span>
                {idx > 0 ? (
                  <span
                    className="text-[10px] mono"
                    style={{ color: up ? 'var(--color-confirmed)' : down ? 'var(--color-warm)' : 'var(--color-fg-faint)' }}
                  >
                    {v != null && prev != null ? deltaText(v - prev) : '\u2014\u2014'}
                  </span>
                ) : null}
              </span>
            )
          })}
        </div>
      ))}
      {showFpr ? (
        <div className="grid grid-cols-[200px_repeat(3,minmax(0,1fr))] items-center gap-4 py-2">
          <TechLabel>false positive rate</TechLabel>
          {stageKeys.map((k) => {
            const v = asNum(rows[k]?.false_positive_rate)
            return (
              <span
                key={k}
                className="text-[13px] mono"
                style={{ color: v === 0 ? 'var(--color-confirmed)' : 'var(--color-warm)' }}
              >
                {v == null ? '\u2014\u2014' : v.toFixed(3)}
              </span>
            )
          })}
        </div>
      ) : null}
    </div>
  )
}

function DeltaTile({ label, value, format }: { label: string; value: number | undefined; format: (v: number) => string }) {
  return (
    <div className="rounded-sm border border-line bg-panel px-4 py-4">
      <TechLabel>{label}</TechLabel>
      <div className="display mt-2 text-3xl leading-none">{value != null ? format(value) : '\u2014\u2014'}</div>
    </div>
  )
}

interface RunRow {
  scenario_id: string
  is_benign: boolean
  events: number
  detections: number
  chains: number
  raw: number | null
  corr: number | null
  recon: number | null
  correct: boolean | null
}

function getRunRows(run: unknown): RunRow[] {
  const list = ((run as { per_scenario?: Array<Record<string, unknown>> }).per_scenario ?? [])
  return list.map((s) => {
    const stagesRec = (s.stages ?? {}) as Record<string, Record<string, unknown>>
    const f1Of = (stage: string): number | null => {
      const t = stagesRec[stage]?.techniques as { f1?: number | null } | undefined
      return t?.f1 ?? null
    }
    return {
      scenario_id: String(s.scenario_id ?? 'unknown'),
      is_benign: Boolean(s.is_benign),
      events: Number(s.events ?? 0),
      detections: Number(s.detections ?? 0),
      chains: Number(s.chains ?? 0),
      raw: f1Of('raw_detection'),
      corr: f1Of('correlation'),
      recon: f1Of('reconstruction'),
      correct: (stagesRec.reconstruction?.correct as boolean | undefined) ?? null,
    }
  })
}

function readStageF1(metrics: unknown, stage: string): number | null {
  const m = metrics as Record<string, Record<string, Record<string, number | null>>>
  return m?.technique_level?.[stage]?.f1 ?? null
}

export default function Evaluate() {
  const stages = useStageComparison()
  const runs = useEvaluationRuns()
  const qc = useQueryClient()
  const toast = useToast()
  const [notice, setNotice] = useState<string | null>(null)

  const run = useMutation({
    mutationFn: () => runEvaluation({ persist: true }),
    onSuccess: (result) => {
      const id = 'RUN ' + String(result.run_id ?? '')
      setNotice(id + ' COMPLETE')
      toast.success(id + ' COMPLETE')
      void qc.invalidateQueries({ queryKey: ['stages'] })
      void qc.invalidateQueries({ queryKey: ['evaluation-runs'] })
      void qc.invalidateQueries({ queryKey: ['stats'] })
    },
    onError: (error: Error) => {
      setNotice('EVALUATION FAILED \u2014 ' + error.message)
      toast.error('EVALUATION FAILED \u2014 ' + error.message)
    },
  })

  if (stages.isError && !stages.data) {
    return (
      <ErrorState
        title="EVALUATION DATA UNAVAILABLE"
        message={stages.error instanceof Error ? stages.error.message : undefined}
        onRetry={() => void stages.refetch()}
      />
    )
  }

  const data = stages.data
  const delta = data?.delta ?? {}
  const latestRun = runs.data?.items?.[0]

  return (
    <div className="mx-auto max-w-[1400px] px-8 py-10">
      <header className="mb-8 flex flex-wrap items-end justify-between gap-6">
        <div>
          <TechLabel>Ground-truth comparison of the three pipeline stages</TechLabel>
          <h1 className="display mt-2 text-5xl tracking-tight">EVALUATION</h1>
        </div>
        <div className="flex items-center gap-4">
          {notice ? <span className="max-w-md text-[11px] text-fg-muted mono">{notice}</span> : null}
          <button
            onClick={() => run.mutate()}
            disabled={run.isPending}
            className="rounded-sm border border-line-strong px-5 py-2 text-[11px] tracking-[0.16em] text-fg transition-colors hover:bg-white/8 disabled:opacity-40"
          >
            {run.isPending ? 'EVALUATING\u2026' : 'RUN EVALUATION'}
          </button>
        </div>
      </header>

      {stages.isLoading && !stages.data ? (
        <section className="grid grid-cols-[1fr_auto_1fr_auto_1fr] items-stretch gap-3" aria-busy="true" aria-label="Loading evaluation">
          {[0, 1, 2].map((i) => (
            <div key={i} className="flex items-center gap-3">
              <div className="h-40 flex-1 animate-pulse rounded-sm border border-line bg-panel" />
              {i < 2 ? <div className="flex items-center px-1 text-fg-faint">{'\u2192'}</div> : null}
            </div>
          ))}
        </section>
      ) : (
        <section className="mb-10 grid grid-cols-[1fr_auto_1fr_auto_1fr] items-stretch gap-3">
          {STAGES.map((stage, i) => (
            <div key={stage.key} className="flex items-center gap-3">
              <div className="flex-1 rounded-sm border border-line bg-panel px-5 py-5">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold tracking-[0.18em] text-fg">{stage.label}</span>
                  <span className="text-[10px] text-fg-faint mono">{i + 1}/3</span>
                </div>
                <div className="mt-1 text-[11px] text-fg-faint">{stage.sub}</div>
                <div className="mt-4 flex items-end gap-5">
                  <div>
                    <div className="display text-4xl leading-none">{f1(asF1(data?.technique_level?.[stage.key]?.f1))}</div>
                    <TechLabel className="mt-1.5 block !text-[9px]">Technique F1</TechLabel>
                  </div>
                  <div>
                    <div className="display text-2xl leading-none text-fg-muted">{f1(asF1(data?.event_level?.[stage.key]?.f1))}</div>
                    <TechLabel className="mt-1 block !text-[9px]">Event F1</TechLabel>
                  </div>
                </div>
              </div>
              {i < 2 ? <div className="flex items-center px-1 text-fg-faint">{'\u2192'}</div> : null}
            </div>
          ))}
        </section>
      )}

      {/* metric sets */}
      <section className="mb-10 overflow-hidden rounded-sm border border-line bg-panel px-5">
        <MetricBlock title="Technique level" rows={data?.technique_level} />
        <MetricBlock title="Event level" rows={data?.event_level} />
        <MetricBlock title="Attack detection" rows={data?.attack_detection} showFpr />
      </section>

      {/* deltas */}
      <section className="mb-10 grid grid-cols-2 gap-3 md:grid-cols-4">
        <DeltaTile label="Chain accuracy" value={asNum(delta.chain_accuracy)} format={(v) => (v * 100).toFixed(0) + '%'} />
        <DeltaTile label="Detection latency" value={asNum(delta.mean_detection_latency_seconds)} format={(v) => v.toFixed(0) + 's'} />
        <DeltaTile label="Throughput" value={asNum(delta.events_per_second)} format={(v) => v.toFixed(0) + '/s'} />
        <DeltaTile
          label="Technique F1 vs raw (recon)"
          value={asNum(delta.technique_f1_reconstruction_vs_raw)}
          format={deltaText}
        />
      </section>

      {/* per-scenario detail */}
      <section className="mb-10">
        <div className="mb-3 flex items-center justify-between">
          <TechLabel>Per-scenario detail {latestRun ? '\u2014 run #' + latestRun.id : ''}</TechLabel>
          <span className="text-[11px] text-fg-faint mono">
            {latestRun
              ? latestRun.events_processed + ' events \u00b7 ' + latestRun.duration_seconds + 's'
              : 'no persisted run'}
          </span>
        </div>
        <div className="overflow-x-auto rounded-sm border border-line">
          <table className="w-full border-collapse text-left text-[11px]">
            <thead>
              <tr className="border-b border-line bg-panel">
                {['SCENARIO', 'TYPE', 'EVENTS', 'DETECTIONS', 'CHAINS', 'RAW F1', 'CORR F1', 'RECON F1', 'CORRECT'].map(
                  (h) => (
                    <th key={h} className="px-4 py-2.5 font-medium tracking-[0.12em] text-fg-faint uppercase">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {(latestRun ? getRunRows(latestRun) : []).map((row) => (
                <tr key={row.scenario_id} className="border-b border-line/60 last:border-0">
                  <td className="px-4 py-2.5 text-fg mono">{row.scenario_id}</td>
                  <td
                    className="px-4 py-2.5"
                    style={{ color: row.is_benign ? 'var(--color-confirmed)' : 'var(--color-risk)' }}
                  >
                    {row.is_benign ? 'BENIGN' : 'ATTACK'}
                  </td>
                  <td className="px-4 py-2.5 text-fg-muted mono">{row.events}</td>
                  <td className="px-4 py-2.5 text-fg-muted mono">{row.detections}</td>
                  <td className="px-4 py-2.5 text-fg-muted mono">{row.chains}</td>
                  <td className="px-4 py-2.5 text-fg-muted mono">{f1(row.raw)}</td>
                  <td className="px-4 py-2.5 text-fg-muted mono">{f1(row.corr)}</td>
                  <td className="px-4 py-2.5 text-fg-muted mono">{f1(row.recon)}</td>
                  <td className="px-4 py-2.5">
                    {row.correct == null ? (
                      <span className="text-fg-faint">{'\u2014\u2014'}</span>
                    ) : row.correct ? (
                      <span style={{ color: 'var(--color-confirmed)' }}>YES</span>
                    ) : (
                      <span style={{ color: 'var(--color-risk)' }}>NO</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {runs.data && runs.data.items.length > 1 ? (
        <section>
          <TechLabel className="mb-2 block">Run history</TechLabel>
          <ul className="space-y-1">
            {runs.data.items.map((r) => (
              <li key={r.id} className="flex items-center gap-6 border-b border-line py-2 text-[11px] text-fg-muted">
                <span className="text-fg mono">#{r.id}</span>
                <span className="mono">{r.created_at}</span>
                <span className="mono">{r.events_processed} events</span>
                <span className="mono">{r.duration_seconds}s</span>
                <span className="mono">recon F1 {f1(readStageF1(r.metrics, 'reconstruction'))}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  )
}
