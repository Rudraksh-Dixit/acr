import type { NetworkViewOut } from '../../api/types'
import type { NetworkConnection, DnsQuery } from '../../api/types'
import { fmtClock, severityColor } from '../../lib/format'
import { TechLabel } from '../ui/primitives'

export default function NetworkView({
  network,
  onSelectEvent,
}: {
  network: NetworkViewOut | undefined
  onSelectEvent: (eventId: string) => void
}) {
  const connections = (network?.connections ?? []) as unknown as NetworkConnection[]
  const dns = (network?.dns_queries ?? []) as unknown as DnsQuery[]
  const externals = network?.external_destinations ?? []

  if (connections.length === 0 && dns.length === 0 && externals.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-[11px] tracking-[0.14em] text-fg-faint uppercase">No network activity in this chain</p>
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="border-b border-line px-4 py-2">
        <TechLabel>Network — connections, DNS and external destinations</TechLabel>
      </div>

      {externals.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
          <span className="text-[9.5px] tracking-[0.14em] text-fg-faint uppercase">External</span>
          {externals.map((d) => (
            <span
              key={d}
              className="rounded-sm border px-2 py-0.5 text-[11px] mono"
              style={{ color: 'var(--color-warm)', borderColor: 'rgba(217,164,65,0.4)' }}
            >
              {d}
            </span>
          ))}
        </div>
      ) : null}

      {connections.length > 0 ? (
        <div className="border-b border-line">
          <div className="grid grid-cols-[120px_1fr_70px_1fr_130px] gap-3 border-b border-line/70 px-4 py-1.5 text-[9.5px] tracking-[0.14em] text-fg-faint uppercase">
            <span>time</span>
            <span>source</span>
            <span>proto</span>
            <span>destination</span>
            <span>process</span>
          </div>
          {connections.map((c, i) => (
            <button
              key={`${c.event_id ?? i}`}
              disabled={!c.event_id}
              onClick={() => c.event_id && onSelectEvent(c.event_id)}
              className="grid w-full grid-cols-[120px_1fr_70px_1fr_130px] items-center gap-3 border-b border-line/40 px-4 py-2 text-left transition-colors enabled:hover:bg-white/4"
            >
              <span className="flex items-center gap-2 text-[10.5px] text-fg-faint mono">
                <span
                  className="h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: severityColor[c.severity ?? 'INFO'] ?? 'var(--color-normal)' }}
                />
                {fmtClock(c.timestamp)}
              </span>
              <span className="truncate text-[11.5px] text-fg-muted mono">
                {c.source_ip ?? '—'}
              </span>
              <span className="text-[10.5px] text-fg-faint uppercase mono">{c.protocol ?? '—'}</span>
              <span className="truncate text-[11.5px] text-fg mono" style={{ color: 'var(--color-warm)' }}>
                {c.destination_ip ?? '—'}
                {c.destination_port != null ? `:${c.destination_port}` : ''}
              </span>
              <span className="truncate text-[11px] text-fg-muted mono">{c.process ?? '—'}</span>
            </button>
          ))}
        </div>
      ) : null}

      {dns.length > 0 ? (
        <div>
          <div className="grid grid-cols-[120px_1fr_1fr_130px] gap-3 border-b border-line/70 px-4 py-1.5 text-[9.5px] tracking-[0.14em] text-fg-faint uppercase">
            <span>time</span>
            <span>query</span>
            <span>resolved ip</span>
            <span>process</span>
          </div>
          {dns.map((q, i) => (
            <button
              key={`${q.event_id ?? i}`}
              disabled={!q.event_id}
              onClick={() => q.event_id && onSelectEvent(q.event_id)}
              className="grid w-full grid-cols-[120px_1fr_1fr_130px] items-center gap-3 border-b border-line/40 px-4 py-2 text-left transition-colors enabled:hover:bg-white/4"
            >
              <span className="text-[10.5px] text-fg-faint mono">{fmtClock(q.timestamp)}</span>
              <span className="truncate text-[11.5px] text-fg mono">
                {String(q.query_name ?? q.domain ?? '—')}
              </span>
              <span className="truncate text-[11.5px] text-fg-muted mono">{q.destination_ip ?? '—'}</span>
              <span className="truncate text-[11px] text-fg-muted mono">{q.process ?? '—'}</span>
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )
}
