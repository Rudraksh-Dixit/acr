import { useVirtualizer } from '@tanstack/react-virtual'
import { AnimatePresence, motion } from 'framer-motion'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { getEvent } from '../api/events'
import { useEvents } from '../hooks/queries'
import type { EventDetailOut, EventOut } from '../api/types'
import { EmptyState, ErrorState, SeverityDot, TechLabel } from '../components/ui/primitives'
import { useDebounced } from '../hooks/useDebounced'
import { fmtClock, fmtDay } from '../lib/format'
import { useQuery } from '@tanstack/react-query'

const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const EVENT_TYPES = [
  'LOGIN_SUCCESS',
  'LOGIN_ATTEMPT',
  'PROCESS_CREATED',
  'FILE_CREATED',
  'FILE_MODIFIED',
  'NETWORK_CONNECTION',
  'DNS_QUERY',
  'REGISTRY_MODIFIED',
  'SERVICE_CREATED',
  'PRIVILEGE_CHANGE',
  'REMOTE_EXECUTION',
  'AUTHENTICATION',
  'LOGOUT',
]

function Field({ label, value, mono = true }: { label: string; value?: string | number | null; mono?: boolean }) {
  if (value == null || value === '') return null
  return (
    <div className="flex flex-col gap-1 border-b border-line py-2">
      <TechLabel>{label}</TechLabel>
      <div className={`text-[12px] leading-relaxed break-all text-fg ${mono ? 'mono' : ''}`}>{String(value)}</div>
    </div>
  )
}

function EventDrawer({ eventId, onClose }: { eventId: string; onClose: () => void }) {
  const detail = useQuery({
    queryKey: ['event', eventId],
    queryFn: () => getEvent(eventId),
    staleTime: 10_000,
  })
  const data: EventDetailOut | undefined = detail.data

  return (
    <motion.aside
      initial={{ x: 40, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 40, opacity: 0 }}
      transition={{ duration: 0.28, ease: [0.2, 0.7, 0.2, 1] }}
      className="fixed inset-y-12 right-0 z-30 flex w-[440px] max-w-[92vw] flex-col border-l border-line bg-panel"
    >
      <div className="flex items-center justify-between border-b border-line px-4 py-3">
        <div className="flex items-center gap-3">
          <TechLabel>Evidence</TechLabel>
          <span className="text-[11px] text-fg-muted mono">{eventId}</span>
        </div>
        <button onClick={onClose} className="text-[11px] tracking-[0.14em] text-fg-faint hover:text-fg" aria-label="Close evidence">
          CLOSE ✕
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-4 pb-8">
        {detail.isLoading ? <div className="py-6 text-[12px] text-fg-faint">LOADING EVENT…</div> : null}
        {detail.isError ? (
          <div className="py-6 text-[12px] text-risk mono">{detail.error instanceof Error ? detail.error.message : 'ERROR'}</div>
        ) : null}

        {data ? (
          <>
            <div className="flex items-center gap-3 border-b border-line py-3">
              <SeverityDot severity={data.severity} />
              <span className="text-sm font-medium text-fg">{data.event_type}</span>
              <span className="ml-auto text-[11px] text-fg-faint mono">{fmtDay(data.timestamp)} {fmtClock(data.timestamp)}</span>
            </div>

            <Field label="Host" value={data.host} />
            <Field label="User" value={data.user} />
            <Field label="Process" value={data.process_name} />
            <Field label="PID" value={data.process_id} />
            <Field label="Parent process" value={data.parent_process} />
            <Field label="Command line" value={data.command_line} />
            <Field label="File path" value={data.file_path} />
            <Field label="File hash" value={data.file_hash} />
            <Field label="Domain" value={data.domain} />
            <Field label="Source IP" value={data.source_ip} />
            <Field label="Destination IP" value={data.destination_ip} />
            <Field label="Ports" value={data.destination_port ? `${data.source_port ?? '——'} → ${data.destination_port}` : null} />
            <Field label="Protocol" value={data.protocol} />
            <Field
              label="Technique"
              value={data.technique_id ? `${data.technique_id} — ${data.technique_name ?? ''}`.trim() : null}
            />
            <Field label="Tactic" value={data.tactic} mono={false} />
            <Field label="Source" value={data.source} />
            <Field label="Scenario" value={data.scenario_id} />

            {data.chain_id ? (
              <div className="py-3">
                <Link
                  to={`/investigate/${data.chain_id}`}
                  className="inline-flex items-center gap-2 rounded-sm border border-line-strong px-3 py-1.5 text-[11px] tracking-[0.14em] text-fg hover:bg-white/8"
                >
                  OPEN CHAIN {data.chain_id} →
                </Link>
              </div>
            ) : null}

            {data.detections && data.detections.length > 0 ? (
              <section className="mt-4">
                <TechLabel className="mb-2 block">Detections ({data.detections.length})</TechLabel>
                <ul className="space-y-2">
                  {data.detections.map((d, i) => (
                    <li key={i} className="rounded-sm border border-line bg-raised p-3">
                      <div className="flex items-center gap-2">
                        <SeverityDot severity={d.severity} />
                        <span className="text-[12px] font-medium text-fg">{d.rule_name}</span>
                        <span className="ml-auto text-[10px] text-fg-faint mono">{d.rule_id}</span>
                      </div>
                      {d.description ? <p className="mt-1.5 text-[11px] leading-relaxed text-fg-muted">{d.description}</p> : null}
                      {d.technique_id ? (
                        <div className="mt-1.5 text-[11px] text-fg-faint mono">
                          {d.technique_id} {d.technique_name}
                        </div>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}

            {data.entities && data.entities.length > 0 ? (
              <section className="mt-4">
                <TechLabel className="mb-2 block">Entities ({data.entities.length})</TechLabel>
                <ul className="flex flex-wrap gap-1.5">
                  {data.entities.map((e, i) => (
                    <li key={i} className="rounded-sm border border-line px-2 py-1 text-[11px] text-fg-muted">
                      <span className="text-fg-faint">{e.entity_type}</span>{' '}
                      <span className="mono">{e.value}</span>
                      {e.role ? <span className="ml-1 text-fg-faint">({e.role})</span> : null}
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}

            {data.raw ? (
              <section className="mt-4">
                <TechLabel className="mb-2 block">Raw record</TechLabel>
                <pre className="max-h-60 overflow-auto rounded-sm border border-line bg-base p-3 text-[10px] leading-relaxed text-fg-muted mono">
                  {JSON.stringify(data.raw, null, 2)}
                </pre>
              </section>
            ) : null}
          </>
        ) : null}
      </div>
    </motion.aside>
  )
}

export default function Events() {
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebounced(search, 300)
  const [eventType, setEventType] = useState('')
  const [host, setHost] = useState('')
  const [user, setUser] = useState('')
  const [severity, setSeverity] = useState('')
  const [limit, setLimit] = useState(500)
  const [selected, setSelected] = useState<string | null>(null)

  const query = useMemo(
    () => ({
      search: debouncedSearch || undefined,
      event_type: eventType || undefined,
      host: host || undefined,
      user: user || undefined,
      severity: severity || undefined,
      limit,
      offset: 0,
    }),
    [debouncedSearch, eventType, host, user, severity, limit],
  )

  const events = useEvents(query)
  const items: EventOut[] = events.data?.items ?? []
  const total = events.data?.total ?? 0

  // filter option probes (first 500 events)
  const probe = useEvents({ limit: 500 })
  const hosts = useMemo(() => [...new Set((probe.data?.items ?? []).map((e) => e.host).filter(Boolean) as string[])].sort(), [probe.data])
  const users = useMemo(() => [...new Set((probe.data?.items ?? []).map((e) => e.user).filter(Boolean) as string[])].sort(), [probe.data])

  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 36,
    overscan: 12,
  })

  useEffect(() => {
    virtualizer.scrollToOffset(0)
  }, [query, virtualizer])

  const selectCls =
    'w-full rounded-sm border border-line bg-raised px-2 py-1.5 text-[11px] text-fg-muted outline-none hover:border-line-strong'

  return (
    <div className="relative flex h-[calc(100dvh-3rem)]">
      {/* filter rail */}
      <aside className="w-56 shrink-0 overflow-y-auto border-r border-line px-4 py-5">
        <TechLabel className="mb-3 block">Query</TechLabel>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="command · file · process"
          className="mb-4 w-full rounded-sm border border-line bg-raised px-2.5 py-2 text-[12px] text-fg placeholder:text-fg-faint outline-none focus:border-line-strong mono"
        />

        <div className="space-y-3">
          <div>
            <TechLabel className="mb-1 block">Event type</TechLabel>
            <select value={eventType} onChange={(e) => setEventType(e.target.value)} className={selectCls}>
              <option value="">ALL</option>
              {EVENT_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <TechLabel className="mb-1 block">Host</TechLabel>
            <select value={host} onChange={(e) => setHost(e.target.value)} className={selectCls}>
              <option value="">ALL</option>
              {hosts.map((h) => (
                <option key={h} value={h}>{h}</option>
              ))}
            </select>
          </div>
          <div>
            <TechLabel className="mb-1 block">User</TechLabel>
            <select value={user} onChange={(e) => setUser(e.target.value)} className={selectCls}>
              <option value="">ALL</option>
              {users.map((u) => (
                <option key={u} value={u}>{u}</option>
              ))}
            </select>
          </div>
          <div>
            <TechLabel className="mb-1 block">Severity</TechLabel>
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={selectCls}>
              <option value="">ALL</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>

        {(eventType || host || user || severity || search) && (
          <button
            onClick={() => {
              setSearch('')
              setEventType('')
              setHost('')
              setUser('')
              setSeverity('')
            }}
            className="mt-4 text-[10px] tracking-[0.14em] text-fg-faint hover:text-fg"
          >
            CLEAR FILTERS ✕
          </button>
        )}

        <div className="mt-6 border-t border-line pt-4">
          <div className="text-[11px] text-fg-faint">
            <span className="text-fg-muted mono">{items.length}</span> loaded /{' '}
            <span className="text-fg-muted mono">{total}</span> total
          </div>
          {items.length < total ? (
            <button
              onClick={() => setLimit((l) => l + 500)}
              className="mt-2 text-[10px] tracking-[0.14em] text-fg-muted hover:text-fg"
            >
              LOAD MORE ↓
            </button>
          ) : null}
        </div>
      </aside>

      {/* stream */}
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="grid grid-cols-[92px_170px_1fr_1fr_1fr_150px_90px] items-center gap-3 border-b border-line px-4 py-2">
          {['TIME', 'EVENT', 'HOST', 'USER', 'PROCESS', 'TECHNIQUE', 'SEVERITY'].map((h) => (
            <TechLabel key={h} className="!text-[9px]">{h}</TechLabel>
          ))}
        </div>

        <div ref={parentRef} className="flex-1 overflow-y-auto">
          {events.isError ? (
            <ErrorState
              title="EVENT STREAM UNAVAILABLE"
              message={events.error instanceof Error ? events.error.message : undefined}
              onRetry={() => void events.refetch()}
            />
          ) : events.isLoading ? (
            <div className="p-6 text-[12px] text-fg-faint">QUERYING TELEMETRY…</div>
          ) : items.length === 0 ? (
            <EmptyState title="NO EVENTS MATCH" body="Adjust the query or ingest telemetry to populate the stream." />
          ) : (
            <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
              {virtualizer.getVirtualItems().map((row) => {
                const e = items[row.index]
                return (
                  <button
                    key={e.event_id}
                    onClick={() => setSelected(e.event_id)}
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      height: row.size,
                      transform: `translateY(${row.start}px)`,
                    }}
                    className={`grid grid-cols-[92px_170px_1fr_1fr_1fr_150px_90px] items-center gap-3 border-b border-line/60 px-4 text-left text-[11px] transition-colors hover:bg-white/4 ${
                      selected === e.event_id ? 'bg-white/6' : ''
                    }`}
                  >
                    <span className="text-fg-faint mono">{fmtClock(e.timestamp)}</span>
                    <span className="truncate text-fg-muted">{e.event_type}</span>
                    <span className="truncate text-fg-muted mono">{e.host ?? '——'}</span>
                    <span className="truncate text-fg-muted mono">{e.user ?? '——'}</span>
                    <span className="truncate text-fg-faint mono">{e.process_name ?? e.file_path ?? e.domain ?? '——'}</span>
                    <span className="truncate text-fg-faint mono">{e.technique_id ?? '——'}</span>
                    <span className="flex items-center gap-2">
                      <SeverityDot severity={e.severity} />
                      <span className="text-fg-faint">{e.severity ?? 'INFO'}</span>
                    </span>
                  </button>
                )
              })}
            </div>
          )}
        </div>
      </div>

      <AnimatePresence>{selected ? <EventDrawer eventId={selected} onClose={() => setSelected(null)} /> : null}</AnimatePresence>
    </div>
  )
}
