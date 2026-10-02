/** Formatting helpers — pure, timezone-agnostic display functions. */

export function fmtClock(iso: string | null | undefined): string {
  if (!iso) return '——:——:——'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '——:——:——'
  return d.toISOString().slice(11, 19)
}

export function fmtDay(iso: string | null | undefined): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return d.toISOString().slice(0, 10)
}

export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds)) return '——'
  if (seconds < 1) return '<1 sec'
  if (seconds < 60) return `${Math.round(seconds)} sec`
  const m = Math.floor(seconds / 60)
  const s = Math.round(seconds % 60)
  return `${m} min ${String(s).padStart(2, '0')} sec`
}

export function pct(value: number | null | undefined, digits = 0): string {
  if (value == null || Number.isNaN(value)) return '——'
  return `${value.toFixed(digits)}%`
}

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export const riskColor: Record<RiskLevel | string, string> = {
  LOW: 'var(--color-normal)',
  MEDIUM: 'var(--color-warm)',
  HIGH: 'var(--color-risk)',
  CRITICAL: 'var(--color-risk)',
}

export const severityColor: Record<string, string> = {
  INFO: 'var(--color-normal)',
  LOW: 'var(--color-normal)',
  MEDIUM: 'var(--color-warm)',
  HIGH: 'var(--color-risk)',
  CRITICAL: 'var(--color-risk)',
}

export function riskRank(level: string | null | undefined): number {
  switch (level) {
    case 'CRITICAL':
      return 3
    case 'HIGH':
      return 2
    case 'MEDIUM':
      return 1
    default:
      return 0
  }
}

/** short id for display: ACR-0042 -> 0042 */
export function shortChain(id: string): string {
  const parts = id.split('-')
  return parts.length > 1 ? parts[parts.length - 1] : id
}

export function countOf(value: unknown): number {
  return Array.isArray(value) ? value.length : 0
}

/** stable css color for a string (used for lane dots) */
export function hashHue(text: string): number {
  let h = 0
  for (let i = 0; i < text.length; i++) h = (h * 31 + text.charCodeAt(i)) % 360
  return h
}
