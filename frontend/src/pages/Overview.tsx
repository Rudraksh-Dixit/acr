import { Link } from 'react-router-dom'
import type { CoverageOut, DatasetCatalogOut, DatasetRunListOut, StageComparisonOut } from '../api/types'
import { ErrorState, StatCell, TechLabel } from '../components/ui/primitives'
import { useChains, useCoverage, useDatasetRuns, useDatasets, useStageComparison } from '../hooks/queries'
import { useConfig, usePipeline, useStats } from '../hooks/systemQueries'

const PIPELINE_LABELS: Record<string, string> = {
  ingestion: 'INGEST',
  detection: 'DETECT',
  correlation: 'CORRELATE',
  reconstruction: 'RECONSTRUCT',
}

function f1(v: unknown): string {
  return typeof v === 'number' && !Number.isNaN(v) ? v.toFixed(3) : '\u2014\u2014'
}

function num(v: unknown): number | undefined {
  return typeof v === 'number' && !Number.isNaN(v) ? v : undefined
}

function StatTiles({ stats }: { stats: ReturnType<typeof useStats>['data'] }) {
  if (!stats) return null
  const c = stats.counts
  return (
    <section className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-line bg-line md:grid-cols-5">
      {[
        { label: 'events', value: c.events, sub: 'in store' },
        { label: 'detections', value: c.detections, sub: 'rule matches' },
        { label: 'chains', value: c.chains, sub: `${c.attack_chains} attack` },
        { label: 'entities', value: c.entities, sub: 'extracted' },
        { label: 'techniques', value: c.techniques, sub: 'ATT&CK mapped' },
      ].map((tile) => (
        <div key={tile.label} className="bg-panel px-5 py-4">
          <StatCell label={tile.label} value={tile.value} sub={tile.sub} />
        </div>
      ))}
    </section>
  )
}

function PipelineStrip({ pipeline }: { pipeline: ReturnType<typeof usePipeline>['data'] }) {
  if (!pipeline?.stages?.length) return null
  return (
    <section>
      <TechLabel className="mb-2 block">Pipeline — live counts from /api/pipeline</TechLabel>
      <div className="grid gap-3 md:grid-cols-3">
        {pipeline.stages.map((stage, i) => {
          const detail = (stage.last_run_detail ?? {}) as Record<string, unknown>
          const label = PIPELINE_LABELS[stage.stage] ?? stage.stage.toUpperCase()
          const provenance =
            typeof detail.dataset_label === 'string'
              ? `last ingest: ${detail.dataset_label}`
              : typeof detail.chains === 'number'
                ? `${detail.chains} chains rebuilt`
                : stage.description
          return (
            <div key={stage.stage} className="relative rounded-sm border border-line bg-panel px-4 py-3.5">
              <div className="flex items-baseline justify-between">
                <span className="text-[11px] font-semibold tracking-[0.16em] text-fg">{label}</span>
                <span className="text-[10px] text-fg-faint mono">{i + 1}/{pipeline.stages.length}</span>
              </div>
              <div className="display mt-2 text-3xl leading-none">
                {stage.count ?? '\u2014\u2014'}
              </div>
              <div className="mt-1.5 truncate text-[10px] text-fg-faint mono" title={provenance}>
                {provenance}
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}

function KillChainBar({
  stages,
  tacticToStage,
  coverage,
}: {
  stages: string[]
  tacticToStage: Record<string, number>
  coverage: CoverageOut | undefined
}) {
  if (!stages.length) return null
  const perStage = stages.map((name, i) => {
    const stageNo = i + 1
    const count = (coverage?.tactics ?? []).reduce(
      (acc, t) => acc + (tacticToStage[t.tactic] === stageNo ? t.count : 0),
      0,
    )
    return { stageNo, name, count }
  })
  const max = Math.max(1, ...perStage.map((s) => s.count))
  const total = perStage.reduce((acc, s) => acc + s.count, 0)
  return (
    <section>
      <div className="mb-2 flex items-baseline justify-between">
        <TechLabel>Kill chain coverage — observed ATT&amp;CK techniques per stage</TechLabel>
        <span className="text-[10px] text-fg-faint mono">{total} mapped</span>
      </div>
      <div className="grid grid-cols-7 gap-2 rounded-sm border border-line bg-panel p-4">
        {perStage.map((s) => {
          const empty = s.count === 0
          return (
            <div key={s.stageNo} className="flex min-w-0 flex-col items-stretch gap-1.5">
              <div className="flex h-16 items-end">
                <div
                  className="w-full rounded-sm transition-[height] duration-500"
                  style={{
                    height: `${Math.max(empty ? 3 : 8, (s.count / max) * 100)}%`,
                    background: empty
                      ? 'var(--color-line-strong)'
                      : `color-mix(in srgb, var(--color-risk) ${40 + (s.count / max) * 60}%, transparent)`,
                  }}
                  title={`${s.name}: ${s.count} observed technique(s)`}
                />
              </div>
              <div className="truncate text-center text-[9px] font-medium tracking-[0.1em] text-fg-muted uppercase">
                {s.stageNo}. {s.name}
              </div>
              <div
                className="text-center text-[11px] mono"
                style={{ color: empty ? 'var(--color-fg-faint)' : 'var(--color-fg)' }}
              >
                {s.count}
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}

function EvaluationSnapshot({ stages }: { stages: StageComparisonOut | undefined }) {
  const level = stages?.technique_level
  const delta = stages?.delta ?? {}
  const row = (label: string, key: 'raw_detection' | 'correlation' | 'reconstruction') => (
    <div className="flex items-center justify-between border-b border-line/50 py-1.5 last:border-0">
      <TechLabel>{label}</TechLabel>
      <span className="text-[13px] text-fg mono">{f1(level?.[key]?.f1)}</span>
    </div>
  )
  return (
    <div className="rounded-sm border border-line bg-panel px-5 py-4">
      <div className="mb-2 flex items-center justify-between">
        <TechLabel>Evaluation — technique F1 by stage</TechLabel>
        <Link to="/evaluate" className="text-[10px] tracking-[0.14em] text-fg-faint hover:text-fg-muted">
          OPEN →
        </Link>
      </div>
      {level ? (
        <>
          {row('raw detection', 'raw_detection')}
          {row('correlation', 'correlation')}
          {row('reconstruction', 'reconstruction')}
          <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-[11px] text-fg-muted mono">
            <span>chain accuracy {num(delta.chain_accuracy) == null ? '\u2014\u2014' : `${(num(delta.chain_accuracy)! * 100).toFixed(0)}%`}</span>
            <span>latency {num(delta.mean_detection_latency_seconds) == null ? '\u2014\u2014' : `${num(delta.mean_detection_latency_seconds)}s`}</span>
            <span>throughput {num(delta.events_per_second) == null ? '\u2014\u2014' : `${num(delta.events_per_second)}/s`}</span>
          </div>
        </>
      ) : (
        <p className="text-[11px] text-fg-faint mono">no evaluation runs yet — open EVALUATE to run one</p>
      )}
    </div>
  )
}

function DataSnapshot({
  catalog,
  runs,
}: {
  catalog: DatasetCatalogOut | undefined
  runs: DatasetRunListOut | undefined
}) {
  const items = catalog?.items ?? []
  const synthetic = items.filter((d) => d.kind === 'synthetic').length
  const real = items.filter((d) => d.kind === 'real').length
  const last = runs?.items?.[0]
  const gt = last?.evaluation as { ground_truth?: boolean; note?: string | null } | undefined
  return (
    <div className="rounded-sm border border-line bg-panel px-5 py-4">
      <div className="mb-2 flex items-center justify-between">
        <TechLabel>Data catalog</TechLabel>
        <Link to="/data" className="text-[10px] tracking-[0.14em] text-fg-faint hover:text-fg-muted">
          OPEN →
        </Link>
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-1 text-[12px] text-fg-muted">
        <span style={{ color: 'var(--color-confirmed)' }}>{synthetic} synthetic</span>
        <span style={{ color: 'var(--color-risk)' }}>{real} real</span>
        <span className="text-fg-faint mono">{runs?.total ?? 0} runs</span>
      </div>
      {last ? (
          <div className="mt-3 space-y-1 text-[11px] text-fg-faint mono">
            <div className="text-fg-muted">
              #{last.id} {last.label} — {num(last.counts?.events_stored) ?? '?'} stored
              {num(last.counts?.events_skipped) ? `, ${num(last.counts?.events_skipped)} skipped` : ''}
            </div>
          <div style={{ color: gt?.ground_truth ? 'var(--color-confirmed)' : 'var(--color-warm)' }}>
            {gt?.ground_truth ? 'ground truth — metrics computed' : (gt?.note ?? 'no ground truth, precision/recall not computed')}
          </div>
        </div>
      ) : (
        <p className="mt-3 text-[11px] text-fg-faint mono">no dataset runs yet</p>
      )}
    </div>
  )
}

export default function Overview() {
  const stats = useStats()
  const pipeline = usePipeline()
  const config = useConfig()
  const coverage = useCoverage()
  const evaluation = useStageComparison()
  const chains = useChains({ limit: 5 })
  const datasets = useDatasets()
  const datasetRuns = useDatasetRuns()

  if (stats.isError && !stats.data) {
    return (
      <ErrorState
        title="OVERVIEW UNAVAILABLE"
        message={stats.error instanceof Error ? stats.error.message : undefined}
        onRetry={() => void stats.refetch()}
      />
    )
  }

  const killChain = config.data?.kill_chain
  const topChains = chains.data?.items ?? []

  return (
    <div className="mx-auto max-w-[1400px] px-8 py-10">
      <header className="mb-8 flex flex-wrap items-end justify-between gap-6">
        <div>
          <TechLabel>Every number on this page comes from the live API</TechLabel>
          <h1 className="display mt-2 text-5xl tracking-tight">OVERVIEW</h1>
        </div>
        <div className="flex items-center gap-5 text-[11px] text-fg-faint mono">
          <Link to="/investigate" className="hover:text-fg-muted">INVESTIGATE →</Link>
          <Link to="/chains" className="hover:text-fg-muted">CHAINS →</Link>
          <Link to="/system" className="hover:text-fg-muted">SYSTEM →</Link>
        </div>
      </header>

      {stats.isLoading && !stats.data ? (
        <div className="space-y-6" aria-busy="true" aria-label="Loading overview">
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-sm border border-line bg-line md:grid-cols-5">
            {[0, 1, 2, 3, 4].map((i) => (
              <div key={i} className="h-24 animate-pulse bg-panel" />
            ))}
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-24 animate-pulse rounded-sm border border-line bg-panel" />
            ))}
          </div>
          <div className="grid gap-3 lg:grid-cols-3">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-44 animate-pulse rounded-sm border border-line bg-panel" />
            ))}
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          <StatTiles stats={stats.data} />
          <PipelineStrip pipeline={pipeline.data} />
          {killChain ? (
            <KillChainBar
              stages={killChain.stages}
              tacticToStage={killChain.tactic_to_stage}
              coverage={coverage.data}
            />
          ) : null}

          <section className="grid gap-3 lg:grid-cols-3">
            <EvaluationSnapshot stages={evaluation.data} />
            <DataSnapshot catalog={datasets.data} runs={datasetRuns.data} />
            <div className="rounded-sm border border-line bg-panel px-5 py-4">
              <div className="mb-2 flex items-center justify-between">
                <TechLabel>Highest-risk chains</TechLabel>
                <Link to="/chains" className="text-[10px] tracking-[0.14em] text-fg-faint hover:text-fg-muted">
                  OPEN →
                </Link>
              </div>
              {topChains.length ? (
                <ul className="space-y-1.5">
                  {topChains.map((chain) => (
                    <li key={chain.chain_id} className="flex items-center justify-between gap-3 text-[11px]">
                      <Link
                        to={`/investigate/${chain.chain_id}`}
                        className="truncate text-fg-muted hover:text-fg"
                      >
                        <span className="text-fg mono">{chain.chain_id}</span>{' '}
                        {chain.is_attack ? 'attack' : 'benign'} · {chain.event_count ?? '?'} ev
                      </Link>
                      <span className="shrink-0 text-fg-faint mono">
                        {typeof chain.confidence?.score === 'number'
                          ? `${chain.confidence.score.toFixed(1)}%`
                          : '\u2014'}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-[11px] text-fg-faint mono">no chains yet</p>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
