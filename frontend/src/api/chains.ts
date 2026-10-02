import { http } from './client'
import type {
  ChainDetail,
  ChainListOut,
  EvidenceBlock,
  FeedbackComment,
  FeedbackRequest,
  GraphOut,
  InvestigationOut,
  NetworkViewOut,
  ProcessTreeNode,
  TimelineOut,
} from './types'

export interface ChainQuery {
  status?: string
  is_attack?: boolean
  scenario_id?: string
  host?: string
  min_confidence?: number
  limit?: number
  offset?: number
}

export function listChains(query: ChainQuery = {}): Promise<ChainListOut> {
  return http.get<ChainListOut>('/api/chains', query as Record<string, string | number | boolean | undefined>)
}

export function getChain(chainId: string): Promise<ChainDetail> {
  return http.get<ChainDetail>(`/api/chains/${encodeURIComponent(chainId)}`)
}

export function getChainTimeline(chainId: string, includeInferred = true): Promise<TimelineOut> {
  return http.get<TimelineOut>(`/api/chains/${encodeURIComponent(chainId)}/timeline`, {
    include_inferred: includeInferred,
  })
}

export function getChainEvidence(chainId: string): Promise<EvidenceBlock> {
  return http.get<EvidenceBlock>(`/api/chains/${encodeURIComponent(chainId)}/evidence`)
}

export function getChainGraph(chainId: string): Promise<GraphOut> {
  return http.get<GraphOut>(`/api/chains/${encodeURIComponent(chainId)}/graph`)
}

export function getChainProcessTree(chainId: string): Promise<ProcessTreeNode[]> {
  return http.get<ProcessTreeNode[]>(`/api/chains/${encodeURIComponent(chainId)}/process-tree`)
}

export function getChainNetwork(chainId: string): Promise<NetworkViewOut> {
  return http.get<NetworkViewOut>(`/api/chains/${encodeURIComponent(chainId)}/network`)
}

export function getInvestigation(chainId: string, includeInferred = true): Promise<InvestigationOut> {
  return http.get<InvestigationOut>(`/api/investigation/${encodeURIComponent(chainId)}`, {
    include_inferred: includeInferred,
  })
}

export function getGlobalGraph(scenarioId?: string, limit = 400): Promise<GraphOut> {
  return http.get<GraphOut>('/api/graphs', { scenario_id: scenarioId, limit })
}

export function confirmChain(chainId: string, body: FeedbackComment = {}): Promise<ChainDetail> {
  return http.post<ChainDetail>(`/api/chains/${encodeURIComponent(chainId)}/confirm`, body)
}

export function dismissChain(chainId: string, body: FeedbackComment = {}): Promise<ChainDetail> {
  return http.post<ChainDetail>(`/api/chains/${encodeURIComponent(chainId)}/dismiss`, body)
}

export function postFeedback(chainId: string, body: FeedbackRequest): Promise<ChainDetail> {
  return http.post<ChainDetail>(`/api/chains/${encodeURIComponent(chainId)}/feedback`, body)
}
