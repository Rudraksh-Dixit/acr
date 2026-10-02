import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { generateScenarios, resetScenarios } from '../api/scenarios'
import type { ScenarioCatalogItem, ScenarioGenerateOut } from '../api/types'
import { EmptyState, ErrorState, TechLabel } from '../components/ui/primitives'
import { useScenarios } from '../hooks/queries'
import { useToast } from '../lib/toast'

const PIPELINE_STAGES = [
  'INGESTING\u2026',
  'NORMALIZING\u2026',
  'DETECTING\u2026',
  'CORRELATING\u2026',
  'RECONSTRUCTING\u2026',
]

/** split the backend description narrative into visual beats (real text) */
function beats(description: string): string[] {
  return description
    .split(/\s*(?:->|→|=>)\s*/)
    .map((s) => s.trim())
    .filter(Boolean)
}

function ScenarioRow({
  scenario,
  selected,
  onSelect,
}: {
  scenario: ScenarioCatalogItem
  selected: boolean
  onSelect: () => void
}) {
  const narrative = beats(scenario.description)
  return (
    <button
      onClick={onSelect}
      className={`group w-full border-b border-line px-4 py-5 text-left transition-colors ${
        selected ? 'bg-white/5' : 'hover:bg-white/3'
      }`}
    >
      <div className="flex items-center gap-4">
        <span className="text-[11px] text-fg-faint mono">{scenario.scenario_id}</span>
        <span className="display text-xl text-fg">{scenario.name}</span>
        <span
          className="ml-auto rounded-sm border px-2 py-0.5 text-[10px] tracking-[0.14em]"
          style={{
            color: scenario.is_benign ? 'var(--color-confirmed)' : 'var(--color-risk)',
            borderColor: scenario.is_benign ? 'var(--color-confirmed-deep)' : 'var(--color-risk-deep)',
          }}
        >
          {scenario.is_benign ? 'BENIGN' : 'ATTACK'}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1.5">
        {narrative.map((beat, i) => (
          <span key={i} className="flex items-center gap-2">
            {i > 0 ? <span className="text-fg-faint">{'\u2193'}</span> : null}
            <span
              className={`rounded-sm border px-2 py-0.5 text-[10px] tracking-[0.1em] ${
                selected ? 'border-line-strong text-fg' : 'border-line text-fg-muted'
              }`}
            >
              {beat.toUpperCase()}
            </span>
          </span>
        ))}
      </div>
    </button>
  )
}

export default function Simulate() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const toast = useToast()
  const scenarios = useScenarios()
  const [selected, setSelected] = useState<string | null>(null)
  const [stage, setStage] = useState(-1)
  const [result, setResult] = useState<ScenarioGenerateOut | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmReset, setConfirmReset] = useState(false)
  const timerRef = useRef<number | null>(null)

  useEffect(() => {
    return () => {
      if (timerRef.current) window.clearInterval(timerRef.current)
    }
  }, [])

  const generate = useMutation({
    mutationFn: (scenarioId: string) =>
      generateScenarios({ scenario_ids: [scenarioId], ingest: true, reconstruct: true, include_ground_truth: true }),
    onMutate: () => {
      setError(null)
      setResult(null)
      setStage(0)
      timerRef.current = window.setInterval(() => {
        setStage((s) => (s < PIPELINE_STAGES.length - 1 ? s + 1 : s))
      }, 450)
    },
    onSuccess: (data) => {
      if (timerRef.current) window.clearInterval(timerRef.current)
      setStage(PIPELINE_STAGES.length)
      setResult(data)
      toast.success(`SCENARIO COMPLETE \u2014 ${data.events_stored} events, ${data.detections} detections, ${data.chains} chains`)
      void qc.invalidateQueries({ queryKey: ['chains'] })
      void qc.invalidateQueries({ queryKey: ['events'] })
      void qc.invalidateQueries({ queryKey: ['stats'] })
      void qc.invalidateQueries({ queryKey: ['global-graph'] })
      void qc.invalidateQueries({ queryKey: ['pipeline'] })
    },
    onError: (err: Error) => {
      if (timerRef.current) window.clearInterval(timerRef.current)
      setStage(-1)
      setError(err.message)
      toast.error('SCENARIO FAILED \u2014 ' + err.message)
    },
  })

  const reset = useMutation({
    mutationFn: () => resetScenarios({ confirm: true, reconstruct: false }),
    onSuccess: () => {
      setConfirmReset(false)
      toast.success('STORE RESET')
      void qc.invalidateQueries()
    },
    onError: (err: Error) => {
      setError(err.message)
      toast.error('RESET FAILED \u2014 ' + err.message)
    },
  })

  if (scenarios.isError) {
    return (
      <ErrorState
        title="SCENARIO CATALOG UNAVAILABLE"
        message={scenarios.error instanceof Error ? scenarios.error.message : undefined}
        onRetry={() => void scenarios.refetch()}
      />
    )
  }

  const items = scenarios.data?.items ?? []
  const active = items.find((s) => s.scenario_id === selected) ?? null
  const running = generate.isPending
  const firstChainId = result?.scenarios?.flatMap((s) => s.chain_ids ?? [])[0]

  return (
    <div className="mx-auto max-w-[1500px] px-8 py-10">
      <header className="mb-8 flex flex-wrap items-end justify-between gap-6">
        <div>
          <TechLabel>Synthetic telemetry against real detection &amp; reconstruction</TechLabel>
          <h1 className="display mt-2 text-5xl tracking-tight">SIMULATE</h1>
        </div>
        <button
          onClick={() => (confirmReset ? reset.mutate() : setConfirmReset(true))}
          onBlur={() => setConfirmReset(false)}
          disabled={reset.isPending}
          className="rounded-sm border px-4 py-2 text-[11px] tracking-[0.14em] transition-colors disabled:opacity-40"
          style={{
            color: confirmReset ? 'var(--color-risk)' : 'var(--color-fg-muted)',
            borderColor: confirmReset ? 'var(--color-risk)' : 'var(--color-line-strong)',
          }}
        >
          {reset.isPending ? 'RESETTING\u2026' : confirmReset ? 'CLICK AGAIN TO CLEAR ALL TELEMETRY' : 'RESET TELEMETRY'}
        </button>
      </header>

      <div className="grid grid-cols-1 gap-8 lg:grid-cols-[1.1fr_1fr]">
        {/* catalog */}
        <section className="overflow-hidden rounded-sm border border-line">
          <div className="border-b border-line bg-panel px-4 py-2.5">
            <TechLabel>Scenario catalog ({items.length})</TechLabel>
          </div>
          {scenarios.isLoading ? (
            <div className="p-6 text-[12px] text-fg-faint">LOADING CATALOG…</div>
          ) : items.length === 0 ? (
            <EmptyState title="NO SCENARIOS REGISTERED" />
          ) : (
            items.map((s) => (
              <ScenarioRow
                key={s.scenario_id}
                scenario={s}
                selected={selected === s.scenario_id}
                onSelect={() => {
                  setSelected(s.scenario_id)
                  setResult(null)
                  setError(null)
                }}
              />
            ))
          )}
        </section>

        {/* stage runner */}
        <section className="rounded-sm border border-line bg-panel">
          <div className="border-b border-line px-4 py-2.5">
            <TechLabel>Generation run</TechLabel>
          </div>

          <div className="px-5 py-5">
            {!active ? (
              <p className="text-[12px] leading-relaxed text-fg-faint">
                Select a scenario to arm the pipeline. Generation writes real telemetry into the store, runs detection
                and reconstructs chains — exactly like CLI <span className="mono">python -m acr generate</span>.
              </p>
            ) : (
              <>
                <div className="mb-5 flex items-center gap-3">
                  <span className="text-[11px] text-fg-faint mono">{active.scenario_id}</span>
                  <span className="display text-2xl">{active.name}</span>
                </div>

                {/* pipeline stages */}
                <ol className="mb-6 space-y-2.5">
                  {PIPELINE_STAGES.map((label, i) => {
                    const state = stage > i ? 'done' : stage === i ? 'active' : 'pending'
                    return (
                      <li key={label} className="flex items-center gap-3">
                        <span
                          className="inline-block h-1.5 w-1.5 rounded-full"
                          style={{
                            background:
                              state === 'done'
                                ? 'var(--color-confirmed)'
                                : state === 'active'
                                  ? 'var(--color-fg)'
                                  : 'var(--color-line-strong)',
                          }}
                        />
                        <span
                          className={`text-[11px] tracking-[0.16em] ${
                            state === 'pending' ? 'text-fg-faint/50' : 'text-fg-muted'
                          }`}
                        >
                          {label}
                        </span>
                        {state === 'active' ? (
                          <span className="ml-2 h-px flex-1 animate-pulse bg-white/25" />
                        ) : null}
                      </li>
                    )
                  })}
                </ol>

                {!result && !running ? (
                  <button
                    onClick={() => generate.mutate(active.scenario_id)}
                    className="w-full rounded-sm border border-fg/70 bg-white/6 px-5 py-3 text-[11px] font-medium tracking-[0.2em] text-fg transition-colors hover:bg-white/12"
                  >
                    GENERATE TELEMETRY
                  </button>
                ) : null}

                {running && stage >= PIPELINE_STAGES.length - 1 ? (
                  <div className="text-[11px] text-fg-faint mono">waiting for engine…</div>
                ) : null}
              </>
            )}

            {error ? (
              <div className="mt-4 rounded-sm border px-3 py-2 text-[11px] text-risk mono" style={{ borderColor: 'var(--color-risk-deep)' }}>
                {error}
              </div>
            ) : null}

            {/* result */}
            {result ? (
              <div className="mt-6 border-t border-line pt-5">
                <div className="flex items-center gap-3">
                  <span className="inline-block h-2 w-2 rounded-full" style={{ background: 'var(--color-confirmed)' }} />
                  <span className="display text-lg tracking-tight">CHAIN RECONSTRUCTED</span>
                </div>

                <div className="mt-4 grid grid-cols-4 gap-3">
                  {[
                    ['EVENTS', result.events_stored],
                    ['DETECTIONS', result.detections],
                    ['CHAINS', result.chains],
                    ['ATTACKS', result.attack_chains],
                  ].map(([label, value]) => (
                    <div key={String(label)} className="rounded-sm border border-line px-3 py-2.5">
                      <div className="display text-xl">{String(value)}</div>
                      <TechLabel className="!text-[9px]">{String(label)}</TechLabel>
                    </div>
                  ))}
                </div>

                {result.scenarios?.[0]?.ground_truth ? (
                  <div className="mt-4">
                    <TechLabel className="mb-1.5 block">Ground truth (returned by engine)</TechLabel>
                    <div className="flex flex-wrap gap-1.5">
                      {(() 	=> {
                        const gt = result.scenarios[0].ground_truth as Record<string, unknown>
                        const techs = Array.isArray(gt.techniques) ? (gt.techniques as string[]) : []
                        return techs.map((t) => (
                          <span key={t} className="rounded-sm border border-line px-2 py-0.5 text-[10px] text-fg-muted mono">
                            {t}
                          </span>
                        ))
                      })()}
                    </div>
                  </div>
                ) : null}

                <div className="mt-5 flex flex-wrap gap-3">
                  {firstChainId ? (
                    <button
                      onClick={() => navigate(`/investigate/${firstChainId}`)}
                      className="rounded-sm border border-fg/60 px-4 py-2 text-[11px] tracking-[0.16em] text-fg hover:bg-white/8"
                    >
                      OPEN RECONSTRUCTED CHAIN {'\u2192'}
                    </button>
                  ) : (
                    <span className="text-[11px] text-fg-faint">
                      No chain was reconstructed — benign or undetected telemetry legitimately yields zero chains.
                    </span>
                  )}
                  <button
                    onClick={() => navigate('/evaluate')}
                    className="rounded-sm border border-line-strong px-4 py-2 text-[11px] tracking-[0.16em] text-fg-muted hover:text-fg"
                  >
                    RUN EVALUATION
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  )
}
