import { AnimatePresence, motion } from 'framer-motion'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getTechnique } from '../api/mitre'
import { useChains, useCoverage, useTactics, useTechniques } from '../hooks/queries'
import { useKillChain, stageLabel } from '../lib/killchain'
import { EmptyState, ErrorState, TechLabel } from '../components/ui/primitives'
import type { TechniqueOut } from '../api/types'

export default function Attack() {
  const tactics = useTactics()
  const techniques = useTechniques(true)
  const coverage = useCoverage()
  const chains = useChains({ limit: 200 })
  const [selected, setSelected] = useState<string | null>(null)

  const observedByTactic = useMemo(() => {
    const map = new Map<string, Set<string>>()
    for (const t of coverage.data?.tactics ?? []) {
      map.set(t.tactic.toUpperCase(), new Set(t.techniques.map((x) => x.technique_id.toUpperCase())))
    }
    return map
  }, [coverage.data])

  const { stages: kcStages, tacticToStage } = useKillChain()

  const byTactic = useMemo(() => {
    const map = new Map<string, TechniqueOut[]>()
    for (const t of techniques.data?.items ?? []) {
      const key = t.tactic.toUpperCase()
      if (!map.has(key)) map.set(key, [])
      map.get(key)!.push(t)
    }
    for (const rows of map.values()) rows.sort((a, b) => a.technique_id.localeCompare(b.technique_id))
    return map
  }, [techniques.data])

  const tacticNames = useMemo(() => {
    const listed = (tactics.data?.items ?? []).map((t) => t.name.toUpperCase())
    return listed.length > 0 ? listed : [...byTactic.keys()]
  }, [tactics.data, byTactic])

  const detail = useQuery({
    queryKey: ['technique', selected],
    queryFn: () => getTechnique(selected as string),
    enabled: !!selected,
    staleTime: 60_000,
  })

  const associatedChains = useMemo(() => {
    if (!selected) return []
    return (chains.data?.items ?? []).filter((c) => (c.techniques ?? []).some((t) => t.technique_id === selected))
  }, [chains.data, selected])

  if (tactics.isError || techniques.isError) {
    return (
      <ErrorState
        title="ATT&CK CATALOG UNAVAILABLE"
        message={techniques.error instanceof Error ? techniques.error.message : undefined}
        onRetry={() => {
          void tactics.refetch()
          void techniques.refetch()
        }}
      />
    )
  }

  const observedTotal = coverage.data?.unique_techniques ?? 0

  return (
    <div className="relative flex h-[calc(100dvh-3rem)] flex-col">
      <header className="flex items-end justify-between border-b border-line px-8 py-6">
        <div>
          <TechLabel>MITRE ATT&CK — observed coverage</TechLabel>
          <h1 className="display mt-1.5 text-4xl tracking-tight">ATT&amp;CK</h1>
        </div>
        <div className="flex items-center gap-8 text-right">
          <div>
            <div className="display text-2xl">{observedTotal}</div>
            <TechLabel>Observed techniques</TechLabel>
          </div>
          <div>
            <div className="display text-2xl">{coverage.data?.unique_tactics ?? '——'}</div>
            <TechLabel>Observed tactics</TechLabel>
          </div>
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <div className="flex-1 overflow-x-auto overflow-y-auto">
          <div className="flex min-w-max">
            {tacticNames.map((tactic) => {
              const rows = byTactic.get(tactic) ?? []
              const observed = observedByTactic.get(tactic) ?? new Set<string>()
              return (
                <section key={tactic} className="w-[260px] shrink-0 border-r border-line">
                  <div className="sticky top-0 z-10 border-b border-line bg-panel/95 px-4 py-3 backdrop-blur">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-[11px] font-semibold tracking-[0.14em] text-fg">{tactic}</div>
                      {tacticToStage[tactic] != null ? (
                        <span
                          className="shrink-0 rounded-sm border border-line px-1.5 py-0.5 text-[9px] tracking-[0.08em] text-fg-faint"
                          title={`Kill chain stage: ${stageLabel(kcStages, tacticToStage[tactic])}`}
                        >
                          KC{tacticToStage[tactic]}
                        </span>
                      ) : null}
                    </div>
                    <TechLabel className="!text-[9px]">
                      {observed.size > 0 ? `${observed.size} observed` : 'not observed'}
                    </TechLabel>
                  </div>
                  <ul className="px-2 py-3">
                    {rows.map((t) => {
                      const isObserved = observed.has(t.technique_id.toUpperCase())
                      const isSelected = selected === t.technique_id
                      return (
                        <li key={t.technique_id}>
                          <button
                            onClick={() => setSelected(t.technique_id)}
                            className={`group mb-1 flex w-full flex-col gap-0.5 rounded-sm border px-2.5 py-2 text-left transition-all ${
                              isSelected
                                ? 'border-white/60 bg-white/6'
                                : isObserved
                                  ? 'border-line-strong bg-raised hover:border-white/40'
                                  : 'border-line/60 bg-transparent opacity-55 hover:opacity-85'
                            }`}
                          >
                            <span className="flex items-center gap-2">
                              <span
                                className="h-1.5 w-1.5 shrink-0 rounded-full"
                                style={{
                                  background: isObserved ? 'var(--color-confirmed)' : 'var(--color-line-strong)',
                                }}
                              />
                              <span className="text-[11px] text-fg-muted mono">{t.technique_id}</span>
                              {t.is_subtechnique ? <span className="text-[9px] text-fg-faint">SUB</span> : null}
                            </span>
                            <span className="text-[12px] leading-snug text-fg">{t.name}</span>
                          </button>
                        </li>
                      )
                    })}
                    {rows.length === 0 ? <li className="px-2 py-3 text-[11px] text-fg-faint">NO TECHNIQUES LOADED</li> : null}
                  </ul>
                </section>
              )
            })}
          </div>
        </div>

        <AnimatePresence>
          {selected ? (
            <motion.aside
              initial={{ x: 40, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: 40, opacity: 0 }}
              transition={{ duration: 0.25 }}
              className="w-[400px] shrink-0 overflow-y-auto border-l border-line bg-panel px-5 py-5"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-[11px] text-fg-muted mono">{selected}</div>
                  <h2 className="display mt-1 text-xl leading-tight text-fg">
                    {detail.data?.name ?? 'LOADING…'}
                  </h2>
                </div>
                <button onClick={() => setSelected(null)} className="text-[11px] text-fg-faint hover:text-fg" aria-label="Close">
                  ✕
                </button>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <span className="rounded-sm border border-line px-2 py-1 text-[10px] tracking-[0.12em] text-fg-muted">
                  {detail.data?.tactic ?? '——'}
                </span>
                <span
                  className="rounded-sm border px-2 py-1 text-[10px] tracking-[0.12em]"
                  style={{
                    color: observedByTactic.get((detail.data?.tactic ?? '').toUpperCase())?.has(selected.toUpperCase())
                      ? 'var(--color-confirmed)'
                      : 'var(--color-fg-faint)',
                    borderColor: 'var(--color-line)',
                  }}
                >
                  {observedByTactic.get((detail.data?.tactic ?? '').toUpperCase())?.has(selected.toUpperCase())
                    ? 'OBSERVED IN TELEMETRY'
                    : 'NOT OBSERVED'}
                </span>
                {detail.data?.kill_chain_stage != null ? (
                  <span
                    className="rounded-sm border border-line px-2 py-1 text-[10px] tracking-[0.12em] text-fg-muted"
                    title="Kill chain stage this technique maps to"
                  >
                    {stageLabel(kcStages, detail.data.kill_chain_stage)}
                  </span>
                ) : null}
              </div>

              {detail.data?.description ? (
                <p className="mt-4 text-[12px] leading-relaxed text-fg-muted">{detail.data.description}</p>
              ) : null}

              {detail.data?.detection_hint ? (
                <section className="mt-5">
                  <TechLabel className="mb-1.5 block">Detection hint</TechLabel>
                  <p className="text-[12px] leading-relaxed text-fg-muted">{detail.data.detection_hint}</p>
                </section>
              ) : null}

              {detail.data?.subtechnique_of ? (
                <section className="mt-5">
                  <TechLabel className="mb-1.5 block">Subtechnique of</TechLabel>
                  <span className="text-[12px] text-fg mono">{detail.data.subtechnique_of}</span>
                </section>
              ) : null}

              <section className="mt-5">
                <TechLabel className="mb-2 block">Associated chains ({associatedChains.length})</TechLabel>
                {associatedChains.length === 0 ? (
                  <p className="text-[11px] text-fg-faint">No reconstructed chain maps to this technique yet.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {associatedChains.map((c) => (
                      <li key={c.chain_id}>
                        <Link
                          to={`/investigate/${c.chain_id}`}
                          className="flex items-center justify-between rounded-sm border border-line px-3 py-2 text-[11px] text-fg-muted hover:border-line-strong hover:text-fg"
                        >
                          <span className="mono">{c.chain_id}</span>
                          <span>
                            {c.risk.level} · {c.confidence.score.toFixed(0)}%
                          </span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </motion.aside>
          ) : null}
        </AnimatePresence>
      </div>

      {tactics.isLoading || techniques.isLoading ? (
        <div className="absolute inset-0 flex items-center justify-center bg-base/60">
          <TechLabel>Loading ATT&CK landscape…</TechLabel>
        </div>
      ) : null}

      {tacticNames.length === 0 && !tactics.isLoading ? <EmptyState title="ATT&CK CATALOG EMPTY" /> : null}
    </div>
  )
}
