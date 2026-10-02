import { AnimatePresence, motion } from 'framer-motion'
import { useRef, useState } from 'react'
import type { TimelineItem } from '../../api/types'
import { fmtClock, severityColor } from '../../lib/format'
import { TechLabel } from '../ui/primitives'

/** Horizontal attack timeline: observed events as points, inferred as open violet rings. */
export default function Timeline({
  items,
  selectedEventId,
  playheadIndex,
  onScrub,
  onSelect,
  playing,
}: {
  items: TimelineItem[]
  selectedEventId: string | null
  playheadIndex: number
  onScrub: (index: number) => void
  onSelect: (item: TimelineItem) => void
  playing: boolean
}) {
  const trackRef = useRef<HTMLDivElement>(null)
  const [hover, setHover] = useState<{ item: TimelineItem; x: number } | null>(null)
  const draggingRef = useRef(false)

  const observed = items.filter((i) => !i.inferred)
  const inferred = items.filter((i) => i.inferred)

  const times = observed.map((i) => (i.timestamp ? Date.parse(i.timestamp) : Number.NaN)).filter((t) => !Number.isNaN(t))
  const t0 = times.length ? Math.min(...times) : 0
  const t1 = times.length ? Math.max(...times) : 1
  const span = Math.max(1, t1 - t0)

  // observed points occupy 0..88% of the track; inferred steps are laid out
  // in the dashed zone from 91% so nothing ever overflows the timeline strip
  const OBSERVED_SPAN = 88

  const xOf = (item: TimelineItem, idx: number): number => {
    if (item.timestamp && !item.inferred) {
      const t = Date.parse(item.timestamp)
      if (!Number.isNaN(t)) return ((t - t0) / span) * OBSERVED_SPAN
    }
    const inferredIdx = item.inferred ? inferred.indexOf(item) : 0
    void idx
    return Math.min(99, 91 + inferredIdx * (7.5 / Math.max(1, inferred.length)))
  }

  const indexFromClientX = (clientX: number): number => {
    const rect = trackRef.current?.getBoundingClientRect()
    if (!rect || observed.length === 0) return 0
    const ratio = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width))
    let best = 0
    let bestDist = Infinity
    items.forEach((item, idx) => {
      if (item.inferred) return
      const dist = Math.abs(xOf(item, idx) / 100 - ratio)
      if (dist < bestDist) {
        bestDist = dist
        best = idx
      }
    })
    return best
  }

  const handlePointer = (e: React.PointerEvent) => {
    if (!draggingRef.current) return
    onScrub(indexFromClientX(e.clientX))
  }

  const label = (item: TimelineItem) =>
    `${fmtClock(item.timestamp)}  ${item.event_type ?? item.kind ?? ''}`

  return (
    <div className="relative select-none border-t border-line bg-panel/92 px-6 pt-3 pb-4 backdrop-blur">
      <div className="mb-2 flex items-center justify-between">
        <TechLabel>
          Timeline — {observed.length} observed{inferred.length > 0 ? ` · ${inferred.length} inferred` : ''}
        </TechLabel>
        <span className="text-[10px] text-fg-faint mono">
          {fmtClock(observed[0]?.timestamp)} → {fmtClock(observed[observed.length - 1]?.timestamp)}
        </span>
      </div>

      <div
        ref={trackRef}
        className="relative h-12 cursor-crosshair"
        onPointerDown={(e) => {
          draggingRef.current = true
          e.currentTarget.setPointerCapture?.(e.pointerId)
          onScrub(indexFromClientX(e.clientX))
        }}
        onPointerUp={() => {
          draggingRef.current = false
        }}
        onPointerMove={handlePointer}
        onPointerLeave={() => setHover(null)}
      >
        {/* baseline */}
        <div className="absolute inset-x-0 top-6 h-px bg-white/12" />
        {/* inferred zone */}
        {inferred.length > 0 ? (
          <div
            className="absolute top-6 h-px"
            style={{
              left: '89.5%',
              width: '10.5%',
              background:
                'repeating-linear-gradient(90deg, var(--color-inferred) 0 4px, transparent 4px 8px)',
              opacity: 0.7,
            }}
          />
        ) : null}

        {/* playhead */}
        <div
          className="absolute top-1 bottom-1 w-px bg-white/70 transition-[left] duration-300"
          style={{ left: `${Math.min(99.5, xOf(items[playheadIndex] ?? items[0], playheadIndex))}%` }}
        >
          <span className="absolute -top-0.5 -left-[3px] h-1.5 w-1.5 rotate-45 bg-white" />
        </div>

        {items.map((item, idx) => {
          const x = xOf(item, idx)
          const isSel = !!selectedEventId && item.event_id === selectedEventId
          const revealed = idx <= playheadIndex || !playing
          return (
            <button
              key={`${item.seq}-${item.event_id ?? item.technique?.['technique_id'] ?? idx}`}
              className="absolute top-6 -translate-x-1/2 -translate-y-1/2"
              style={{ left: `${x}%` }}
              onPointerEnter={(e) => {
                const rect = trackRef.current?.getBoundingClientRect()
                setHover({ item, x: rect ? e.clientX - rect.left : 0 })
              }}
              onPointerLeave={() => setHover(null)}
              onClick={(e) => {
                e.stopPropagation()
                onSelect(item)
              }}
              aria-label={label(item)}
            >
              {item.inferred ? (
                <span
                  className="block h-3 w-3 rounded-full border border-dashed"
                  style={{ borderColor: 'var(--color-inferred)', opacity: revealed ? 1 : 0.25 }}
                />
              ) : (
                <span
                  className="block rounded-full transition-all"
                  style={{
                    width: isSel ? 14 : 9,
                    height: isSel ? 14 : 9,
                    background: severityColor[item.severity ?? 'INFO'] ?? 'var(--color-normal)',
                    boxShadow: isSel ? '0 0 0 4px rgb(255 255 255 / 0.16)' : undefined,
                    opacity: revealed ? 1 : 0.3,
                    transform: `scale(${item.event_id && item.event_id === selectedEventId ? 1.2 : 1})`,
                  }}
                />
              )}
            </button>
          )
        })}

        {/* hover preview */}
        <AnimatePresence>
          {hover ? (
            <motion.div
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.14 }}
              className="pointer-events-none absolute -top-2 z-20 max-w-[340px] -translate-x-1/2 -translate-y-full rounded-sm border border-line-strong bg-over px-3 py-2 shadow-xl"
              style={{ left: Math.max(90, hover.x) }}
            >
              <div className="flex items-center gap-2">
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ background: severityColor[hover.item.severity ?? 'INFO'] ?? 'var(--color-normal)' }}
                />
                <span className="text-[10px] text-fg-faint mono">{fmtClock(hover.item.timestamp)}</span>
                <span className="text-[10.5px] font-medium text-fg">
                  {hover.item.event_type ?? hover.item.kind ?? ''}
                </span>
                {hover.item.inferred ? (
                  <span className="text-[9px] tracking-[0.14em]" style={{ color: 'var(--color-inferred)' }}>
                    INFERRED
                  </span>
                ) : null}
              </div>
              {hover.item.summary ? (
                <div className="mt-1 truncate text-[11px] text-fg-muted">{hover.item.summary}</div>
              ) : null}
              {hover.item.technique ? (
                <div className="mt-0.5 text-[10px] text-fg-faint mono">
                  {String(hover.item.technique['technique_id'] ?? '')} {String(hover.item.technique['name'] ?? '')}
                </div>
              ) : null}
            </motion.div>
          ) : null}
        </AnimatePresence>
      </div>
    </div>
  )
}
