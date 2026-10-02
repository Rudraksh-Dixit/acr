import { AnimatePresence } from 'framer-motion'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import AttackGraph from '../components/graph/AttackGraph'
import ChainRail from '../components/investigation/ChainRail'
import EvidenceOverlay from '../components/investigation/EvidenceOverlay'
import IntelPanel from '../components/investigation/IntelPanel'
import NetworkView from '../components/investigation/NetworkView'
import ProcessTreeView from '../components/investigation/ProcessTree'
import Timeline from '../components/timeline/Timeline'
import { EmptyState, ErrorState, TechLabel } from '../components/ui/primitives'
import {
  useChain,
  useChainEvidence,
  useChainGraph,
  useChainNetwork,
  useChainProcessTree,
  useChainTimeline,
  useChains,
  useGlobalGraph,
} from '../hooks/queries'
import { buildGraphModel } from '../lib/graph'
import { shortChain } from '../lib/format'

type View = 'graph' | 'tree' | 'network'

const VIEWS: Array<{ id: View; label: string }> = [
  { id: 'graph', label: 'ATTACK GRAPH' },
  { id: 'tree', label: 'PROCESS TREE' },
  { id: 'network', label: 'NETWORK' },
]

export default function Investigate() {
  const { chainId } = useParams<{ chainId: string }>()
  const navigate = useNavigate()

  const chainsQ = useChains({ limit: 100 })
  const chainQ = useChain(chainId)
  const chainGraphQ = useChainGraph(chainId)
  const globalQ = useGlobalGraph()
  const timelineQ = useChainTimeline(chainId)
  const evidenceQ = useChainEvidence(chainId)
  const treeQ = useChainProcessTree(chainId)
  const networkQ = useChainNetwork(chainId)

  const [view, setView] = useState<View>('graph')
  const [focusId, setFocusId] = useState<string | null>(null)
  const [playhead, setPlayhead] = useState(-1)
  const [playing, setPlaying] = useState(false)

  const items = useMemo(() => timelineQ.data?.items ?? [], [timelineQ.data])
  const itemsLen = items.length
  const prevChain = useRef<string | undefined>(undefined)

  useEffect(() => {
    if (prevChain.current !== chainId) {
      prevChain.current = chainId
      setFocusId(null)
      setView('graph')
      setPlaying(false)
      setPlayhead(itemsLen - 1)
      return
    }
    if (itemsLen > 0 && (playhead < 0 || playhead > itemsLen - 1)) setPlayhead(itemsLen - 1)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chainId, itemsLen])

  useEffect(() => {
    if (!playing) return
    if (playhead >= itemsLen - 1) {
      setPlaying(false)
      return
    }
    const t = window.setTimeout(() => setPlayhead((p) => p + 1), 620)
    return () => window.clearTimeout(t)
  }, [playing, playhead, itemsLen])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setFocusId(null)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const graphOut = chainId ? chainGraphQ.data : globalQ.data
  const model = useMemo(() => buildGraphModel(graphOut), [graphOut])

  const focusNode = focusId ? model.nodes.find((n) => n.id === focusId) : undefined

  const observedUpTo = useMemo(
    () => items.slice(0, Math.max(0, playhead) + 1).filter((i) => !i.inferred).length,
    [items, playhead],
  )
  const revealCutoff = playhead < 0 ? undefined : observedUpTo

  const focusEvent = (eventId: string) => {
    const node = model.nodes.find((n) => n.event_id === eventId)
    if (node) {
      setFocusId(node.id)
      setView('graph')
    }
  }

  const startReplay = () => {
    if (itemsLen === 0) return
    setPlayhead(0)
    setPlaying(true)
  }

  const graphLoading = chainId ? chainGraphQ.isFetching && !chainGraphQ.data : globalQ.isFetching && !globalQ.data
  const graphError = chainId ? chainQ.isError && !chainQ.data : globalQ.isError && !globalQ.data

  const noChains = !chainsQ.isLoading && (chainsQ.data?.items.length ?? 0) === 0 && !chainId

  return (
    <div className="flex h-[calc(100dvh-3rem)] overflow-hidden">
      <ChainRail
        chains={chainsQ.data?.items ?? []}
        total={chainsQ.data?.total}
        activeId={chainId}
        loading={chainsQ.isLoading}
      />

      <main className="flex min-w-0 flex-1 flex-col">
        {/* workspace header */}
        <header className="flex items-center justify-between gap-4 border-b border-line px-4 py-2">
          <div className="flex min-w-0 items-center gap-4">
            <div className="min-w-0">
              <TechLabel>{chainId ? 'Active chain' : 'Landscape'}</TechLabel>
              <div className="flex items-baseline gap-2">
                <span className="text-[14px] tracking-wide text-fg mono">
                  {chainId ? shortChain(chainId) : 'GLOBAL'}
                </span>
                {chainQ.data ? (
                  <span className="truncate text-[11px] text-fg-faint">
                    {chainQ.data.is_attack ? 'attack chain' : 'routine chain'} · {chainQ.data.event_count} events ·{' '}
                    {chainQ.data.hosts?.length ?? 0} hosts
                    {chainQ.data.scenario_id ? ` · ${chainQ.data.scenario_id}` : ''}
                  </span>
                ) : (
                  <span className="text-[11px] text-fg-faint">
                    {model.nodes.length} nodes · {model.edges.length} edges
                  </span>
                )}
              </div>
            </div>

            <div className="flex items-center gap-1 border-l border-line pl-4">
              {VIEWS.map((v) => (
                <button
                  key={v.id}
                  onClick={() => setView(v.id)}
                  disabled={!chainId && v.id !== 'graph'}
                  className={`rounded-sm px-2.5 py-1.5 text-[10px] tracking-[0.14em] transition-colors disabled:opacity-30 ${
                    view === v.id ? 'bg-white/10 text-fg' : 'text-fg-faint hover:text-fg-muted'
                  }`}
                >
                  {v.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-3">
            {/* legend */}
            <div className="hidden items-center gap-3 border-r border-line pr-3 xl:flex">
              <span className="flex items-center gap-1.5 text-[9.5px] tracking-[0.1em] text-fg-faint uppercase">
                <span className="h-2 w-2 rounded-full bg-white/70" /> observed
              </span>
              <span className="flex items-center gap-1.5 text-[9.5px] tracking-[0.1em] text-fg-faint uppercase">
                <span
                  className="h-2 w-2 rounded-full border border-dashed"
                  style={{ borderColor: 'var(--color-inferred)' }}
                />
                inferred
              </span>
              <span className="flex items-center gap-1.5 text-[9.5px] tracking-[0.1em] text-fg-faint uppercase">
                <span className="h-2 w-2 rounded-full" style={{ background: 'var(--color-warm)' }} /> network
              </span>
            </div>

            {chainId && itemsLen > 0 ? (
              <div className="flex items-center gap-1.5">
                {playing ? (
                  <button
                    onClick={() => setPlaying(false)}
                    className="rounded-sm border border-fg/60 px-3 py-1.5 text-[10px] tracking-[0.14em] hover:bg-white/8"
                  >
                    {'\u23F8'} PAUSE
                  </button>
                ) : (
                  <button
                    onClick={startReplay}
                    className="rounded-sm border border-fg/60 px-3 py-1.5 text-[10px] tracking-[0.14em] hover:bg-white/8"
                  >
                    {'\u25B6'} REPLAY ATTACK
                  </button>
                )}
                <button
                  onClick={() => {
                    setPlaying(false)
                    setPlayhead(itemsLen - 1)
                  }}
                  disabled={playhead >= itemsLen - 1 && !playing}
                  className="rounded-sm border border-line-strong px-2.5 py-1.5 text-[10px] tracking-[0.14em] text-fg-muted transition-colors enabled:hover:bg-white/8 disabled:opacity-30"
                  title="Show full graph"
                >
                  {'\u23F9'}
                </button>
              </div>
            ) : null}
          </div>
        </header>

        {/* stage */}
        <div className="relative min-h-0 flex-1">
          {noChains ? (
            <EmptyState
              title="NO CHAINS RECONSTRUCTED"
              body="The store is empty. Generate a scenario or upload telemetry, then the engine will reconstruct attack chains."
              action={
                <button
                  onClick={() => navigate('/simulate')}
                  className="rounded-sm border border-fg/60 px-4 py-2 text-[11px] tracking-[0.16em] hover:bg-white/8"
                >
                  GENERATE SCENARIO
                </button>
              }
            />
          ) : graphError ? (
            <ErrorState
              title="GRAPH UNAVAILABLE"
              message={chainQ.error instanceof Error ? chainQ.error.message : globalQ.error instanceof Error ? globalQ.error.message : undefined}
              onRetry={() => (chainId ? void chainGraphQ.refetch() : void globalQ.refetch())}
            />
          ) : view === 'graph' ? (
            graphLoading ? (
              <div className="flex h-full items-center justify-center">
                <span className="animate-pulse text-[11px] tracking-[0.18em] text-fg-faint uppercase">
                  Loading graph…
                </span>
              </div>
            ) : (
              <>
                <AttackGraph
                  model={model}
                  focusId={focusId}
                  onNodeClick={setFocusId}
                  revealCutoff={revealCutoff}
                />
                <AnimatePresence>
                  {focusNode ? (
                    <EvidenceOverlay
                      node={focusNode}
                      model={model}
                      items={items}
                      evidence={evidenceQ.data}
                      onClose={() => setFocusId(null)}
                      onFocusEvent={focusEvent}
                    />
                  ) : null}
                </AnimatePresence>
              </>
            )
          ) : view === 'tree' ? (
            treeQ.isLoading ? (
              <div className="flex h-full items-center justify-center">
                <span className="animate-pulse text-[11px] tracking-[0.18em] text-fg-faint uppercase">
                  Loading process tree…
                </span>
              </div>
            ) : treeQ.isError ? (
              <ErrorState title="PROCESS TREE UNAVAILABLE" onRetry={() => void treeQ.refetch()} />
            ) : (
              <ProcessTreeView tree={treeQ.data ?? []} onSelectEvent={focusEvent} />
            )
          ) : networkQ.isLoading ? (
            <div className="flex h-full items-center justify-center">
              <span className="animate-pulse text-[11px] tracking-[0.18em] text-fg-faint uppercase">
                Loading network view…
              </span>
            </div>
          ) : networkQ.isError ? (
            <ErrorState title="NETWORK VIEW UNAVAILABLE" onRetry={() => void networkQ.refetch()} />
          ) : (
            <NetworkView network={networkQ.data} onSelectEvent={focusEvent} />
          )}
        </div>

        {/* timeline */}
        {chainId && itemsLen > 0 ? (
          <Timeline
            items={items}
            selectedEventId={focusNode?.event_id ?? null}
            playheadIndex={playhead}
            onScrub={(i) => {
              setPlaying(false)
              setPlayhead(i)
            }}
            onSelect={(item) => item.event_id && focusEvent(item.event_id)}
            playing={playing}
          />
        ) : null}
      </main>

      <IntelPanel
        chain={chainQ.data}
        evidence={evidenceQ.data}
        loading={chainId ? chainQ.isLoading : false}
        error={chainQ.isError}
        onRetry={() => void chainQ.refetch()}
      />
    </div>
  )
}
