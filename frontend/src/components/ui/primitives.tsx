import type { ReactNode } from 'react'
import { riskColor, severityColor, type RiskLevel } from '../../lib/format'

export function TechLabel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`tech-label ${className}`}>{children}</span>
}

export function StatusDot({ tone = 'ok', pulse = false }: { tone?: 'ok' | 'warn' | 'down'; pulse?: boolean }) {
  const color = tone === 'ok' ? 'var(--color-confirmed)' : tone === 'warn' ? 'var(--color-warm)' : 'var(--color-risk)'
  return (
    <span
      className={pulse ? 'inline-block animate-pulse rounded-full' : 'inline-block rounded-full'}
      style={{ width: 6, height: 6, background: color, boxShadow: `0 0 8px ${color}` }}
    />
  )
}

export function RiskBadge({ level, className = '' }: { level: RiskLevel | string; className?: string }) {
  const color = riskColor[level] ?? 'var(--color-normal)'
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold tracking-[0.14em] uppercase ${className}`}
      style={{ color, borderColor: `color-mix(in srgb, ${color} 40%, transparent)` }}
    >
      <span className="rounded-full" style={{ width: 5, height: 5, background: color }} />
      {level}
    </span>
  )
}

export function SeverityDot({ severity }: { severity?: string | null }) {
  const color = severityColor[severity ?? 'INFO'] ?? 'var(--color-normal)'
  return (
    <span title={severity ?? 'INFO'} className="inline-block rounded-full" style={{ width: 6, height: 6, background: color }} />
  )
}

export function Meter({
  value,
  max = 100,
  color = 'var(--color-fg)',
  height = 3,
  className = '',
}: {
  value: number
  max?: number
  color?: string
  height?: number
  className?: string
}) {
  const ratio = Math.max(0, Math.min(1, max > 0 ? value / max : 0))
  return (
    <div className={`w-full overflow-hidden rounded-full bg-white/8 ${className}`} style={{ height }}>
      <div
        className="h-full rounded-full transition-[width] duration-700 ease-out"
        style={{ width: `${ratio * 100}%`, background: color }}
      />
    </div>
  )
}

export function EmptyState({ title, body, action }: { title: string; body?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 px-8 text-center">
      <div className="tech-label text-fg-faint">{title}</div>
      {body ? <p className="max-w-md text-sm leading-relaxed text-fg-muted">{body}</p> : null}
      {action}
    </div>
  )
}

export function ErrorState({ title, message, onRetry }: { title: string; message?: string; onRetry?: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-8 text-center">
      <div className="text-2xl font-medium tracking-tight text-risk display">{title}</div>
      {message ? <p className="max-w-md text-sm text-fg-muted mono">{message}</p> : null}
      {onRetry ? (
        <button
          onClick={onRetry}
          className="rounded-sm border border-line-strong px-4 py-1.5 text-[11px] tracking-[0.16em] uppercase text-fg transition-colors hover:bg-white/8"
        >
          Retry
        </button>
      ) : null}
    </div>
  )
}

export function StatCell({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <TechLabel>{label}</TechLabel>
      <div className="display text-2xl leading-none" style={{ color: tone }}>
        {value}
      </div>
      {sub ? <div className="text-[11px] text-fg-faint">{sub}</div> : null}
    </div>
  )
}

/** section heading used across panels */
export function PanelHeading({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
      <TechLabel>{children}</TechLabel>
      {right}
    </div>
  )
}
