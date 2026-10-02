import { useNavigate } from 'react-router-dom'
import type { ChainSummary } from '../../api/types'
import { fmtClock, riskColor, shortChain } from '../../lib/format'
import { TechLabel } from '../ui/primitives'

/** Left rail: chain switcher for the investigation workspace. */
export default function ChainRail({
  chains,
  total,
  activeId,
  loading,
}: {
  chains: ChainSummary[]
  total?: number
  activeId?: string
  loading?: boolean
}) {
  const navigate = useNavigate()

  const sorted = [...chains].sort((a, b) => {
    if (a.is_attack !== b.is_attack) return a.is_attack ? -1 : 1
    const rr = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 } as Record<string, number>
    const d = (rr[b.risk.level] ?? 0) - (rr[a.risk.level] ?? 0)
    if (d !== 0) return d
    return b.confidence.score - a.confidence.score
  })

  return (
    <aside className="flex w-[268px] shrink-0 flex-col border-r border-line bg-panel/60">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <TechLabel>Chains</TechLabel>
        <span className="text-[10px] text-fg-faint mono">{total ?? chains.length}</span>
      </div>

      <button
        onClick={() => navigate('/investigate')}
        className={`border-b border-line px-4 py-2.5 text-left transition-colors hover:bg-white/4 ${
          !activeId ? 'bg-white/6' : ''
        }`}
      >
        <span className="text-[11px] tracking-[0.14em] text-fg-muted uppercase">{'\u2190'} Global graph</span>
      </button>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {loading && chains.length === 0 ? (
          <div className="space-y-2 p-3">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="h-14 animate-pulse rounded-sm bg-white/5" />
            ))}
          </div>
        ) : sorted.length === 0 ? (
          <div className="px-4 py-8 text-center">
            <p className="text-[11px] leading-relaxed text-fg-faint">No chains reconstructed yet.</p>
            <button
              onClick={() => navigate('/simulate')}
              className="mt-3 rounded-sm border border-line-strong px-3 py-1.5 text-[10px] tracking-[0.16em] hover:bg-white/8"
            >
              GENERATE A SCENARIO
            </button>
          </div>
        ) : (
          sorted.map((c) => {
            const active = c.chain_id === activeId
            return (
              <button
                key={c.chain_id}
                onClick={() => navigate(`/investigate/${c.chain_id}`)}
                className={`group relative block w-full border-b border-line/70 px-4 py-3 text-left transition-colors ${
                  active ? 'bg-white/7' : 'hover:bg-white/4'
                }`}
              >
                {active ? <span className="absolute inset-y-0 left-0 w-[2px] bg-fg" /> : null}
                <div className="flex items-center justify-between gap-2">
                  <span className={`text-[12px] font-medium tracking-wide mono ${active ? 'text-fg' : 'text-fg-muted'}`}>
                    {shortChain(c.chain_id)}
                  </span>
                  <span
                    className="h-1.5 w-1.5 rounded-full"
                    style={{ background: riskColor[c.risk.level] ?? 'var(--color-normal)' }}
                    title={c.risk.level}
                  />
                </div>
                <div className="mt-1.5 flex items-center justify-between gap-2">
                  <span className="truncate text-[10.5px] text-fg-faint">
                    {c.is_attack ? 'attack' : 'routine'} · {c.event_count} ev · {fmtClock(c.start_time)}
                  </span>
                  <span className="text-[10.5px] text-fg-muted mono">{c.confidence.score}%</span>
                </div>
                {c.status !== 'OPEN' && c.status !== 'REVIEW' ? (
                  <span className="mt-1 inline-block text-[9px] tracking-[0.14em] text-fg-faint uppercase">
                    {c.status}
                  </span>
                ) : null}
              </button>
            )
          })
        )}
      </div>
    </aside>
  )
}
