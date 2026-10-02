import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useChains } from '../hooks/queries'
import ChainPath from '../components/chains/ChainPath'
import { KillChainStrip } from '../components/killchain/KillChainStrip'
import { EmptyState, ErrorState, RiskBadge, TechLabel } from '../components/ui/primitives'
import { countOf, fmtDuration, pct, riskColor, shortChain } from '../lib/format'
import type { ChainSummary } from '../api/types'

type Filter = 'ALL' | 'ATTACK' | 'BENIGN'
type Sort = 'RISK' | 'CONFIDENCE' | 'RECENT'

const TACTIC_ABBR: Record<string, string> = {
  'INITIAL ACCESS': 'INITIAL ACCESS',
  EXECUTION: 'EXECUTION',
  PERSISTENCE: 'PERSISTENCE',
  'PRIVILEGE ESCALATION': 'PRIV ESC',
  'DEFENSE EVASION': 'DEFENSE EVASION',
  'CREDENTIAL ACCESS': 'CREDENTIAL ACCESS',
  DISCOVERY: 'DISCOVERY',
  'LATERAL MOVEMENT': 'LATERAL MOVEMENT',
  COLLECTION: 'COLLECTION',
  'COMMAND AND CONTROL': 'C2',
  EXFILTRATION: 'EXFILTRATION',
  IMPACT: 'IMPACT',
  RECONNAISSANCE: 'RECON',
  'RESOURCE DEVELOPMENT': 'RESOURCE DEV',
}

function riskWeight(level?: string): number {
  return { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 }[level ?? 'LOW'] ?? 0
}

export default function Chains() {
  const navigate = useNavigate()
  const chains = useChains({ limit: 200 })
  const [filter, setFilter] = useState<Filter>('ALL')
  const [sort, setSort] = useState<Sort>('RISK')

  const items = useMemo(() => {
    let rows: ChainSummary[] = chains.data?.items ?? []
    if (filter === 'ATTACK') rows = rows.filter((c) => c.is_attack)
    if (filter === 'BENIGN') rows = rows.filter((c) => !c.is_attack)
    const sorted = [...rows]
    if (sort === 'RISK') {
      sorted.sort((a, b) => riskWeight(b.risk.level) - riskWeight(a.risk.level) || b.confidence.score - a.confidence.score)
    } else if (sort === 'CONFIDENCE') {
      sorted.sort((a, b) => b.confidence.score - a.confidence.score)
    } else {
      sorted.sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? ''))
    }
    return sorted
  }, [chains.data, filter, sort])

  if (chains.isError) {
    return (
      <ErrorState
        title="ACR ENGINE OFFLINE"
        message={chains.error instanceof Error ? chains.error.message : undefined}
        onRetry={() => void chains.refetch()}
      />
    )
  }

  return (
    <div className="mx-auto max-w-[1500px] px-8 py-10">
      <header className="mb-8 flex flex-wrap items-end justify-between gap-6">
        <div>
          <TechLabel>Reconstructed attack chains</TechLabel>
          <h1 className="display mt-2 text-5xl tracking-tight text-fg">CHAINS</h1>
        </div>

        <div className="flex items-center gap-6">
          <div className="flex items-center gap-1">
            {(['ALL', 'ATTACK', 'BENIGN'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-2.5 py-1 text-[10px] tracking-[0.16em] transition-colors ${
                  filter === f ? 'border-b border-fg text-fg' : 'text-fg-faint hover:text-fg-muted'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1">
            <TechLabel className="mr-1">Sort</TechLabel>
            {(['RISK', 'CONFIDENCE', 'RECENT'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setSort(s)}
                className={`px-2 py-1 text-[10px] tracking-[0.14em] transition-colors ${
                  sort === s ? 'text-fg' : 'text-fg-faint hover:text-fg-muted'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
          <span className="text-[11px] text-fg-faint mono">{chains.data?.total ?? '——'}</span>
        </div>
      </header>

      {chains.isLoading ? (
        <div className="space-y-3">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-20 animate-pulse rounded-sm border border-line bg-panel" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          title="NO RECONSTRUCTED CHAINS"
          body="Chains only form around detection seeds. Benign activity or telemetry without detections legitimately produces zero chains — generate an attack scenario in SIMULATE to reconstruct one."
          action={
            <button
              onClick={() => navigate('/simulate')}
              className="mt-2 rounded-sm border border-line-strong px-4 py-2 text-[11px] tracking-[0.16em] text-fg hover:bg-white/8"
            >
              OPEN SIMULATE
            </button>
          }
        />
      ) : (
        <ul className="border-t border-line">
          {items.map((chain) => {
            const color = riskColor[chain.risk.level] ?? 'var(--color-fg)'
            const tactics = chain.tactics ?? []
            return (
              <li key={chain.chain_id}>
                <button
                  onClick={() => navigate(`/investigate/${chain.chain_id}`)}
                  className="group grid w-full grid-cols-[150px_minmax(180px,1fr)_minmax(220px,1.4fr)_auto] items-center gap-6 border-b border-line px-2 py-5 text-left transition-colors hover:bg-white/3"
                >
                  <div className="flex flex-col gap-1.5">
                    <span className="display text-2xl leading-none text-fg">
                      ACR<span className="text-fg-faint">/</span>
                      <span className="mono text-lg">{shortChain(chain.chain_id)}</span>
                    </span>
                    <TechLabel className="!text-[9px]">{chain.status}</TechLabel>
                  </div>

                  <div className="text-fg-faint transition-colors group-hover:text-fg-muted" style={{ color }}>
                    <ChainPath eventCount={countOf(chain.event_count) || 2} color={color} animate={false} />
                  </div>

                  <div className="flex min-w-0 flex-col gap-2">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] tracking-[0.1em] text-fg-muted">
                      {tactics.length > 0 ? (
                        tactics.map((t, i) => (
                          <span key={t} className="flex items-center gap-2">
                            {i > 0 ? <span className="text-fg-faint">→</span> : null}
                            <span className={i === tactics.length - 1 ? 'text-fg' : ''}>{TACTIC_ABBR[t] ?? t}</span>
                          </span>
                        ))
                      ) : (
                        <span className="text-fg-faint">NO TACTICS RECORDED</span>
                      )}
                    </div>
                    <div className="flex items-center gap-4 text-[11px] text-fg-faint">
                      <span>{chain.hosts?.length ?? 0} HOSTS</span>
                      <span>{chain.users?.length ?? 0} USERS</span>
                      <span>{countOf(chain.event_count)} EVENTS</span>
                      {chain.duration_seconds != null ? <span>{fmtDuration(chain.duration_seconds)}</span> : null}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] tracking-[0.14em] text-fg-faint">KILL CHAIN</span>
                      <KillChainStrip covered={chain.kill_chain_stages} compact />
                    </div>
                  </div>

                  <div className="flex items-center gap-6">
                    <div className="flex flex-col items-end gap-1">
                      <RiskBadge level={chain.risk.level} />
                      <span className="text-[11px] text-fg-faint">RISK {chain.risk.score}</span>
                    </div>
                    <div className="flex w-20 flex-col items-end gap-1">
                      <span className="display text-xl leading-none" style={{ color }}>
                        {pct(chain.confidence.score)}
                      </span>
                      <TechLabel className="!text-[9px]">Confidence</TechLabel>
                    </div>
                  </div>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
