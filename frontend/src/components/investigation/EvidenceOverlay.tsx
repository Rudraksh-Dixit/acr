import { motion } from 'framer-motion'
import type { EvidenceBlock, TimelineItem } from '../../api/types'
import type { GraphModel, PositionedNode } from '../../lib/graph'
import { fmtClock, severityColor } from '../../lib/format'
import { TechLabel } from '../ui/primitives'

function relLabel(r: unknown): string {
  if (r && typeof r === 'object') {
    const o = r as Record<string, unknown>
    const rel = String(o.relation ?? o.type ?? o.role ?? 'RELATION')
    const target = o.target ?? o.entity ?? o.value ?? o.name
    return target != null ? `${rel.toLowerCase()} \u2192 ${String(target)}` : rel.toLowerCase()
  }
  return String(r)
}

/** Contextual evidence panel shown when a graph node is selected. */
export default function EvidenceOverlay({
  node,
  model,
  items,
  evidence,
  onClose,
  onFocusEvent,
}: {
  node: PositionedNode
  model: GraphModel
  items: TimelineItem[]
  evidence: EvidenceBlock | undefined
  onClose: () => void
  onFocusEvent: (eventId: string) => void
}) {
  const edges = model.edges.filter((e) => e.source === node.id || e.target === node.id)
  const isEvent = node.type === 'EVENT' && !!node.event_id

  const timelineItem = isEvent ? items.find((i) => i.event_id === node.event_id) : undefined

  const relatedEvidence = !isEvent
    ? []
    : [
        ...(evidence?.observed ?? []),
        ...(evidence?.inferred ?? []),
      ].filter(
        (e) =>
          (e.event_id && e.event_id === node.event_id) ||
          (Array.isArray(e.event_ids) && !!e.event_ids?.includes(node.event_id as string)),
      )

  const label = isEvent ? (timelineItem?.event_type ?? node.label ?? node.type) : (node.label || node.value || node.type)

  return (
    <motion.div
      initial={{ opacity: 0, x: -14 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -14 }}
      transition={{ duration: 0.18, ease: 'easeOut' }}
      className="absolute top-3 bottom-3 left-3 z-10 flex w-[368px] flex-col rounded-sm border border-line-strong bg-over/95 shadow-2xl backdrop-blur"
    >
      <div className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <TechLabel>{node.type} evidence</TechLabel>
          <div className="mt-1 truncate text-[14px] text-fg mono" title={label}>
            {label}
          </div>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 rounded-sm border border-line px-2 py-1 text-[11px] text-fg-muted transition-colors hover:bg-white/8"
          aria-label="Close evidence panel"
        >
          {'\u2715'}
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        {isEvent ? (
          <>
            <dl className="grid grid-cols-[86px_1fr] gap-x-3 gap-y-1.5 text-[11.5px]">
              {[
                ['time', fmtClock(node.timestamp)],
                ['severity', node.severity ?? 'INFO'],
                ['host', node.host],
                ['user', node.user],
                ['technique', node.technique_id],
              ]
                .filter(([, v]) => !!v)
                .map(([k, v]) => (
                  <div key={k} className="contents">
                    <dt className="text-fg-faint">{k}</dt>
                    <dd className="truncate text-fg-muted mono">
                      {k === 'severity' ? (
                        <span className="flex items-center gap-1.5">
                          <span
                            className="h-1.5 w-1.5 rounded-full"
                            style={{
                              background: severityColor[String(v)] ?? 'var(--color-normal)',
                            }}
                          />
                          {String(v)}
                        </span>
                      ) : (
                        String(v)
                      )}
                    </dd>
                  </div>
                ))}
            </dl>

            {node.command_line ? (
              <div className="mt-3">
                <TechLabel>command line</TechLabel>
                <p className="mt-1 rounded-sm border border-line bg-white/3 px-2.5 py-2 text-[11px] leading-snug break-all text-fg-muted mono">
                  {node.command_line}
                </p>
              </div>
            ) : null}

            {timelineItem && (timelineItem.relationships ?? []).length > 0 ? (
              <div className="mt-3">
                <TechLabel>relationships</TechLabel>
                <ul className="mt-1 space-y-1">
                  {(timelineItem.relationships ?? []).map((r, i) => (
                    <li key={i} className="text-[11px] text-fg-muted mono">
                      {relLabel(r)}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {relatedEvidence.length > 0 ? (
              <div className="mt-3">
                <TechLabel>event evidence ({relatedEvidence.length})</TechLabel>
                <ul className="mt-1 space-y-2">
                  {relatedEvidence.map((e, i) => (
                    <li
                      key={i}
                      className="border-l-2 pl-2.5"
                      style={{
                        borderColor: e.inferred ? 'var(--color-inferred)' : 'var(--color-line-strong)',
                      }}
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-[9.5px] tracking-[0.12em] uppercase" style={{ color: e.inferred ? 'var(--color-inferred)' : 'var(--color-confirmed)' }}>
                          {e.inferred ? 'inferred' : 'observed'}
                        </span>
                        <span className="text-[9.5px] text-fg-faint uppercase">{e.type}</span>
                        {e.points != null ? <span className="text-[9.5px] text-fg-faint mono">+{e.points}</span> : null}
                      </div>
                      <p className="mt-0.5 text-[11.5px] leading-snug text-fg-muted">{e.summary}</p>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </>
        ) : null}

        <div className="mt-4">
          <TechLabel>
            connections ({edges.length})
          </TechLabel>
          <ul className="mt-1.5 space-y-1">
            {edges.length === 0 ? (
              <li className="text-[11px] text-fg-faint">No edges attached to this node.</li>
            ) : (
              edges.map((e) => {
                const out = e.source === node.id
                const otherId = out ? e.target : e.source
                const other = model.nodes.find((n) => n.id === otherId)
                return (
                  <li key={e.id} className="flex items-baseline justify-between gap-2 text-[11px]">
                    <span className="text-fg-faint mono">
                      {out ? '\u2192' : '\u2190'} {e.relation.toLowerCase()}
                    </span>
                    <span className="truncate text-right text-fg-muted mono" title={other?.label ?? otherId}>
                      {other?.type === 'EVENT' ? `EVENT ${fmtClock(other.timestamp)}` : (other?.label ?? otherId)}
                    </span>
                  </li>
                )
              })
            )}
          </ul>
        </div>

        {!isEvent ? (
          <div className="mt-4">
            <TechLabel>observed on events</TechLabel>
            <ul className="mt-1.5 space-y-1">
              {edges
                .map((e) => (e.source === node.id ? e.target : e.source))
                .map((id) => model.nodes.find((n) => n.id === id))
                .filter((n): n is PositionedNode => !!n && n.type === 'EVENT')
                .slice(0, 12)
                .map((n) => (
                  <li key={n.id}>
                    <button
                      onClick={() => n.event_id && onFocusEvent(n.event_id)}
                      className="flex w-full items-baseline gap-2 text-left transition-colors hover:text-fg"
                    >
                      <span className="text-[10.5px] text-fg-faint mono">{fmtClock(n.timestamp)}</span>
                      <span className="truncate text-[11.5px] text-fg-muted">{n.label ?? n.event_type}</span>
                    </button>
                  </li>
                ))}
            </ul>
          </div>
        ) : null}
      </div>
    </motion.div>
  )
}
