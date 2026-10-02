import { motion } from 'framer-motion'

/** Mini attack path: one dot per event (capped), tail dots open for inferred steps. */
export default function ChainPath({
  eventCount,
  inferredCount = 0,
  color = 'var(--color-fg)',
  height = 26,
  animate = true,
  maxDots = 14,
}: {
  eventCount: number
  inferredCount?: number
  color?: string
  height?: number
  animate?: boolean
  maxDots?: number
}) {
  const observedDots = Math.max(2, Math.min(maxDots, Math.max(2, eventCount)))
  const inferredDots = Math.min(3, inferredCount)
  const total = observedDots + inferredDots
  const gap = 16
  const width = total * gap

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden className="overflow-visible">
      <line
        x1={gap / 2}
        y1={height / 2}
        x2={(observedDots - 0.5) * gap}
        y2={height / 2}
        stroke="currentColor"
        strokeOpacity={0.35}
        strokeWidth={1}
      />
      {inferredDots > 0 ? (
        <line
          x1={(observedDots - 0.5) * gap}
          y1={height / 2}
          x2={(total - 0.5) * gap}
          y2={height / 2}
          stroke="var(--color-inferred)"
          strokeOpacity={0.5}
          strokeWidth={1}
          strokeDasharray="2 3"
        />
      ) : null}

      {Array.from({ length: observedDots }).map((_, i) => (
        <motion.circle
          key={i}
          cx={(i + 0.5) * gap}
          cy={height / 2}
          r={i === 0 || i === observedDots - 1 ? 4 : 3}
          fill={color}
          initial={animate ? { opacity: 0, scale: 0.4 } : false}
          whileInView={animate ? { opacity: 1, scale: 1 } : undefined}
          viewport={{ once: true }}
          transition={{ delay: i * 0.05, duration: 0.35, ease: 'easeOut' }}
        />
      ))}
      {Array.from({ length: inferredDots }).map((_, i) => (
        <circle
          key={`i${i}`}
          cx={(observedDots + i + 0.5) * gap}
          cy={height / 2}
          r={3}
          fill="none"
          stroke="var(--color-inferred)"
          strokeWidth={1}
          strokeDasharray="1.5 2"
        />
      ))}
    </svg>
  )
}
