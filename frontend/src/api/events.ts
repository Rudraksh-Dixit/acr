import { http } from './client'
import type { EventDetailOut, EventListOut, EventOut, IngestReportOut, IngestRequest } from './types'

export interface EventQuery {
  event_type?: string
  host?: string
  user?: string
  chain_id?: string
  scenario_id?: string
  severity?: string
  start?: string
  end?: string
  search?: string
  limit?: number
  offset?: number
}

export function listEvents(query: EventQuery = {}): Promise<EventListOut> {
  return http.get<EventListOut>('/api/events', query as Record<string, string | number | undefined>)
}

export function getEvent(eventId: string): Promise<EventDetailOut> {
  return http.get<EventDetailOut>(`/api/events/${encodeURIComponent(eventId)}`)
}

export function ingestEvents(body: IngestRequest): Promise<IngestReportOut> {
  return http.post<IngestReportOut>('/api/events', body)
}

export function uploadEventFile(
  file: File,
  opts: { source?: string; scenarioId?: string; reconstruct?: boolean; replaceDuplicates?: boolean } = {},
): Promise<IngestReportOut> {
  const form = new FormData()
  form.append('file', file)
  return http.postForm<IngestReportOut>('/api/events/upload', form, {
    source: opts.source ?? 'web-upload',
    scenario_id: opts.scenarioId,
    reconstruct: opts.reconstruct ?? true,
    replace_duplicates: opts.replaceDuplicates ?? false,
  })
}

export type { EventOut }
