import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { postFeedback } from '../../api/chains'
import type { ChainDetail, EvidenceBlock, FeedbackRequest } from '../../api/types'
import { fmtDuration, pct, riskColor, severityColor } from '../../lib/format'
import { useToast } from '../../lib/toast'
import { ErrorState, Meter, RiskBadge, TechLabel } from '../ui/primitives'

function Section({ title, children, right }: { title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="border-b border-line">
      <div className="flex items-center justify-between px-4 py-2.5">
        <TechLabel>{title}</TechLabel>
        {right}
      </div>
      <div className="px-4 pb-4">{children}</div>
    </section>
  )
}

const STATUS_TONE: Record<string, string> = {
  CONFIRMED: 'var(--color-confirmed)',
  DISMISSED: 'var(--color-fg-faint)',
  BENIGN: 'var(--color-normal)',
  INVESTIGATING: 'var(--color-warm)',
}

function FeedbackControls({ chain }: { chain: ChainDetail }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [comment, setComment] = useState('')

  const fb = useMutation({
    mutationFn: (body: FeedbackRequest) => postFeedback(chain.chain_id, body),
    onSuccess: (_data, vars) => {
      void qc.invalidateQueries({ queryKey: ['chain', chain.chain_id] })
      void qc.invalidateQueries({ queryKey: ['chains'] })
      setComment('')
      toast.success(`${chain.chain_id} \u2192 ${vars.status}`)
    },
    onError: (err: Error) => toast.error(`FEEDBACK FAILED \u2014 ${err.message}`),
  })

  const apply = (status: string, withReason = false) => {
    fb.mutate({ status, comment: comment || null, reason: withReason && comment ? comment : null })
  }

  const currentTone = STATUS_TONE[chain.status]

  return (
    <div>
      <div className="flex items-center justify-between">
        <span className="text-[11px] tracking-[0.14em] text-fg-muted uppercase">Status</span>
        <span
          className="rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold tracking-[0.14em] uppercase"
          style={{
            color: currentTone ?? 'var(--color-fg-muted)',
            borderColor: `color-mix(in srgb, ${currentTone ?? 'var(--color-line-strong)'} 45%, transparent)`,
          }}
        >
          {chain.status}
        </span>
      </div>

      <textarea
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        placeholder="Optional analyst comment / dismissal reason"
        rows={2}
        maxLength={4000}
        className="mt-3 w-full resize-none rounded-sm border border-line bg-transparent px-2.5 py-2 text-[11.5px] text-fg placeholder:text-fg-faint focus:border-line-strong focus:outline-none"
      />

      <div className="mt-2 grid grid-cols-2 gap-2">
        <button
          onClick={() => apply('CONFIRMED')}
          disabled={fb.isPending}
          className="rounded-sm border px-2 py-1.5 text-[10px] tracking-[0.14em] transition-colors disabled:opacity-40"
          style={{ color: 'var(--color-confirmed)', borderColor: 'rgba(70,167,88,0.45)' }}
        >
          CONFIRM CHAIN
        </button>
        <button
          onClick={() => apply('DISMISSED', true)}
          disabled={fb.isPending}
          className="rounded-sm border px-2 py-1.5 text-[10px] tracking-[0.14em] transition-colors disabled:opacity-40"
          style={{ color: 'var(--color-risk)', borderColor: 'rgba(229,72,77,0.45)' }}
        >
          DISMISS
        </button>
        <button
          onClick={() => apply('BENIGN')}
          disabled={fb.isPending}
          className="rounded-sm border border-line-strong px-2 py-1.5 text-[10px] tracking-[0.14em] text-fg-muted transition-colors enabled:hover:bg-white/6 disabled:opacity-40"
        >
          MARK BENIGN
        </button>
        <button
          onClick={() => apply('INVESTIGATING')}
          disabled={fb.isPending}
          className="rounded-sm border border-line-strong px-2 py-1.5 text-[10px] tracking-[0.14em] text-fg-muted transition-colors enabled:hover:bg-white/6 disabled:opacity-40"
        >
          INVESTIGATE
        </button>
      </div>

      {fb.isError ? (
        <p className="mt-2 text-[10.5px] text-risk mono">
          {fb.error instanceof Error ? fb.error.message : 'feedback failed'}
        </p>
      ) : null}

      {chain.analyst_feedback && chain.analyst_feedback.length > 0 ? (
        <ul className="mt-3 space-y-1.5 border-t border-line pt-3">
          {chain.analyst_feedback.map((f, i) => (
            <li key={i} className="text-[10.5px] text-fg-faint">
              <span className="tracking-[0.12em]" style={{ color: STATUS_TONE[f.status] ?? 'var(--color-fg-muted)' }}>
                {f.status}
              </span>
              {f.analyst ? <span> · {f.analyst}</span> : null}
              {f.reason ? <span className="text-fg-muted"> — “{f.reason}”</span> : null}
              {f.comment && !f.reason ? <span className="text-fg-muted"> — “{f.comment}”</span> : null}
              {f.created_at ? <span className="ml-1 mono">{f.created_at.slice(0, 16).replace('T', ' ')}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}

/** Right-hand intelligence panel: chain-level analysis (default view). */
export default function IntelPanel({
  chain,
  evidence,
  loading,
  error,
  onRetry,
}: {
  chain: ChainDetail | undefined
  evidence: EvidenceBlock | undefined
  loading?: boolean
  error?: boolean
  onRetry?: () => void
}) {
  if (error && !chain) {
    return (
      <aside className="w-[372px] shrink-0 border-l border-line bg-panel/60">
        <ErrorState title="CHAIN LOAD FAILED" onRetry={onRetry} />
      </aside>
    )
  }

  if (loading && !chain) {
    return (
      <aside className="w-[372px] shrink-0 border-l border-line bg-panel/60">
        <div className="space-y-3 p-4">
          {[0, 1, 2, 3, 4].map((i) => (
            <div key={i} className="h-16 animate-pulse rounded-sm bg-white/5" />
          ))}
        </div>
      </aside>
    )
  }

  if (!chain) {
    return (
      <aside className="w-[372px] shrink-0 border-l border-line bg-panel/60">
        <div className="border-b border-line px-4 py-2.5">
          <TechLabel>Intelligence</TechLabel>
        </div>
        <div className="px-4 py-6">
          <p className="text-[12px] leading-relaxed text-fg-faint">
            Select a chain from the rail to inspect its confidence derivation, risk factors, inferred gaps and
            evidence.
          </p>
        </div>
      </aside>
    )
  }

  const reasons = chain.confidence.reasons ?? []
  const factors = chain.risk.factors ?? []
  const missing = chain.possible_missing_steps ?? []
  const observedEvidence = evidence?.observed ?? chain.evidence?.filter((e) => !e.inferred) ?? []
  const inferredEvidence = evidence?.inferred ?? chain.evidence?.filter((e) => e.inferred) ?? []
  const maxPoints = Math.max(1, ...reasons.map((r) => r.points))

  return (
    <aside className="flex w-[372px] shrink-0 flex-col border-l border-line bg-panel/60">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <TechLabel>Chain {chain.chain_id}</TechLabel>
        <RiskBadge level={chain.risk.level} />
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {chain.summary ? (
          <div className="border-b border-line px-4 py-3">
            <p className="text-[12.5px] leading-relaxed text-fg-muted">{chain.summary}</p>
          </div>
        ) : null}

        <Section title="Signals">
          <div className="grid grid-cols-3 gap-3">
            <div>
              <div className="flex items-baseline gap-1">
                <span className="display text-3xl leading-none">{chain.confidence.score}</span>
                <span className="text-[11px] text-fg-faint">%</span>
              </div>
              <TechLabel className="!text-[9px]">confidence</TechLabel>
              <Meter
                value={chain.confidence.score}
                color={
                  chain.confidence.score >= 75
                    ? 'var(--color-confirmed)'
                    : chain.confidence.score >= 45
                      ? 'var(--color-warm)'
                      : 'var(--color-risk)'
                }
                className="mt-1.5"
              />
            </div>
            <div>
              <div className="display text-3xl leading-none" style={{ color: riskColor[chain.risk.level] }}>
                {chain.risk.score}
              </div>
              <TechLabel className="!text-[9px]">risk</TechLabel>
              <Meter value={chain.risk.score} color={riskColor[chain.risk.level]} className="mt-1.5" />
            </div>
            <div>
              <div className="display text-3xl leading-none">{fmtDuration(chain.duration_seconds)}</div>
              <TechLabel className="!text-[9px]">duration</TechLabel>
              <div className="mt-1.5 text-[11px] text-fg-faint">
                {chain.event_count} events · {chain.hosts?.length ?? 0} hosts
              </div>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5 border-t border-line pt-3">
            {(chain.tactics ?? []).map((t) => (
              <span
                key={t}
                className="rounded-sm border border-line-strong px-1.5 py-0.5 text-[9.5px] tracking-[0.1em] text-fg-muted uppercase"
              >
                {t}
              </span>
            ))}
          </div>
          {(chain.techniques ?? []).length > 0 ? (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {(chain.techniques ?? []).map((t) => (
                <span
                  key={t.technique_id}
                  className="rounded-sm border px-1.5 py-0.5 text-[10px] mono"
                  style={{ color: 'var(--color-fg-muted)', borderColor: 'var(--color-line)' }}
                  title={t.name}
                >
                  {t.technique_id}
                </span>
              ))}
            </div>
          ) : null}
        </Section>

        <Section title="Why this chain" right={<span className="text-[10px] text-fg-faint mono">links {chain.confidence.links_analyzed ?? '—'}</span>}>
          {reasons.length === 0 ? (
            <p className="text-[11.5px] text-fg-faint">No contributing signals recorded.</p>
          ) : (
            <ul className="space-y-2.5">
              {reasons.map((r) => (
                <li key={r.signal}>
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="text-[11.5px] text-fg-muted">{r.label}</span>
                    <span className="shrink-0 text-[11px] text-fg mono">+{r.points}</span>
                  </div>
                  <Meter value={r.points} max={maxPoints} height={2} className="mt-1" />
                  {r.explanation ? (
                    <p className="mt-1 text-[10.5px] leading-relaxed text-fg-faint">{r.explanation}</p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Risk factors">
          {factors.length === 0 ? (
            <p className="text-[11.5px] text-fg-faint">No elevated risk factors.</p>
          ) : (
            <ul className="space-y-2">
              {factors.map((f) => (
                <li key={f.factor} className="flex items-start justify-between gap-3 border-b border-line/50 pb-2 last:border-0">
                  <span className="min-w-0">
                    <span className="block text-[11.5px] text-fg-muted">{f.factor}</span>
                    {f.detail ? <span className="block text-[10.5px] text-fg-faint">{f.detail}</span> : null}
                  </span>
                  <span className="shrink-0 text-[11px] mono" style={{ color: riskColor[chain.risk.level] }}>
                    +{f.points}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Possible missing steps" right={<span className="text-[10px] text-fg-faint">inferred</span>}>
          {missing.length === 0 ? (
            <p className="text-[11.5px] text-fg-faint">
              Attack path fully observed — no technique gaps to infer.
            </p>
          ) : (
            <ul className="space-y-2">
              {missing.map((m) => (
                <li
                  key={m.technique_id}
                  className="rounded-sm border border-dashed px-3 py-2.5"
                  style={{ borderColor: 'rgba(157,140,255,0.45)', background: 'rgba(157,140,255,0.04)' }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11.5px] text-fg mono" style={{ color: 'var(--color-inferred)' }}>
                      {m.technique_id}
                    </span>
                    <span className="text-[10px] text-fg-faint mono">{pct(m.confidence)}</span>
                  </div>
                  <div className="mt-0.5 text-[12px] text-fg-muted">{m.technique_name}</div>
                  <div className="mt-1 text-[10px] tracking-[0.1em] text-fg-faint uppercase">
                    {m.tactic} · {m.kind.replace(/_/g, ' ').toLowerCase()}
                  </div>
                  {m.explanation || m.reason ? (
                    <p className="mt-1.5 text-[10.5px] leading-relaxed text-fg-faint">
                      Inferred — {m.explanation || m.reason}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section
          title="Evidence"
          right={
            <span className="text-[10px] text-fg-faint mono">
              {observedEvidence.length + inferredEvidence.length} items
            </span>
          }
        >
          {observedEvidence.length === 0 && inferredEvidence.length === 0 ? (
            <p className="text-[11.5px] text-fg-faint">No evidence items attached.</p>
          ) : (
            <ul className="space-y-2">
              {observedEvidence.map((e, i) => (
                <li key={`o-${i}`} className="border-b border-line/50 pb-2 last:border-0">
                  <div className="flex items-center gap-2">
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{ background: severityColor[e.severity ?? 'INFO'] ?? 'var(--color-normal)' }}
                    />
                    <span className="text-[9.5px] tracking-[0.12em] text-fg-faint uppercase">{e.type}</span>
                    <span className="text-[9.5px] tracking-[0.12em] uppercase" style={{ color: 'var(--color-confirmed)' }}>
                      observed
                    </span>
                    {e.technique_id ? (
                      <span className="text-[9.5px] text-fg-faint mono">{e.technique_id}</span>
                    ) : null}
                  </div>
                  <p className="mt-1 text-[11.5px] leading-snug text-fg-muted">{e.summary}</p>
                </li>
              ))}
              {inferredEvidence.map((e, i) => (
                <li
                  key={`i-${i}`}
                  className="rounded-sm border border-dashed px-2.5 py-2"
                  style={{ borderColor: 'rgba(157,140,255,0.4)', background: 'rgba(157,140,255,0.03)' }}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[9.5px] tracking-[0.12em] uppercase" style={{ color: 'var(--color-inferred)' }}>
                      inferred
                    </span>
                    <span className="text-[9.5px] text-fg-faint uppercase">{e.type}</span>
                    {e.confidence != null ? (
                      <span className="text-[9.5px] text-fg-faint mono">{pct(e.confidence)}</span>
                    ) : null}
                  </div>
                  <p className="mt-1 text-[11.5px] leading-snug text-fg-muted">{e.summary}</p>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Analyst feedback">
          <FeedbackControls chain={chain} />
        </Section>
      </div>
    </aside>
  )
}
