import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import {
  confirmChain,
  dismissChain,
  getChain,
  getChainEvidence,
  getChainGraph,
  getChainNetwork,
  getChainProcessTree,
  getChainTimeline,
  getGlobalGraph,
  getInvestigation,
  listChains,
  postFeedback,
} from '../api/chains'
import { getCoverage, listTactics, listTechniques } from '../api/mitre'
import { listEvents, type EventQuery } from '../api/events'
import { listEvaluationRuns, runEvaluation, getStageComparison } from '../api/evaluation'
import { getScenarioCatalog } from '../api/scenarios'
import { getHealth, getPipeline, getStats } from '../api/system'
import type { ChainQuery } from '../api/chains'
import type { AcrGraphOut, ChainListOut, HealthOut, StatsOut, PipelineOut } from '../api/types'
import type { EvaluationRunRequest } from '../api/types'

/* system ----------------------------------------------------------------- */

export function useHealth(): UseQueryResult<HealthOut> {
  return useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 15_000,
    staleTime: 10_000,
  })
}

export function useStats(): UseQueryResult<StatsOut> {
  return useQuery({ queryKey: ['stats'], queryFn: getStats, staleTime: 5_000 })
}

export function usePipeline(): UseQueryResult<PipelineOut> {
  return useQuery({ queryKey: ['pipeline'], queryFn: getPipeline, staleTime: 10_000 })
}

/* chains ------------------------------------------------------------------ */

export function useChains(query: ChainQuery = {}): UseQueryResult<ChainListOut> {
  return useQuery({
    queryKey: ['chains', query],
    queryFn: () => listChains(query),
    staleTime: 5_000,
  })
}

export function useChain(chainId: string | undefined) {
  return useQuery({
    queryKey: ['chain', chainId],
    queryFn: () => getChain(chainId as string),
    enabled: !!chainId,
    staleTime: 5_000,
  })
}

export function useChainGraph(chainId: string | undefined) {
  return useQuery({
    queryKey: ['chain-graph', chainId],
    queryFn: () => getChainGraph(chainId as string),
    enabled: !!chainId,
    staleTime: 5_000,
  })
}

export function useGlobalGraph() {
  return useQuery({
    queryKey: ['global-graph'],
    queryFn: () => getGlobalGraph(),
    staleTime: 5_000,
  })
}

export function useChainTimeline(chainId: string | undefined, includeInferred = true) {
  return useQuery({
    queryKey: ['chain-timeline', chainId, includeInferred],
    queryFn: () => getChainTimeline(chainId as string, includeInferred),
    enabled: !!chainId,
    staleTime: 5_000,
  })
}

export function useChainEvidence(chainId: string | undefined) {
  return useQuery({
    queryKey: ['chain-evidence', chainId],
    queryFn: () => getChainEvidence(chainId as string),
    enabled: !!chainId,
    staleTime: 5_000,
  })
}

export function useChainProcessTree(chainId: string | undefined) {
  return useQuery({
    queryKey: ['chain-process-tree', chainId],
    queryFn: () => getChainProcessTree(chainId as string),
    enabled: !!chainId,
    staleTime: 5_000,
  })
}

export function useChainNetwork(chainId: string | undefined) {
  return useQuery({
    queryKey: ['chain-network', chainId],
    queryFn: () => getChainNetwork(chainId as string),
    enabled: !!chainId,
    staleTime: 5_000,
  })
}

export function useInvestigation(chainId: string | undefined) {
  return useQuery({
    queryKey: ['investigation', chainId],
    queryFn: () => getInvestigation(chainId as string),
    enabled: !!chainId,
    staleTime: 5_000,
  })
}

/* events ------------------------------------------------------------------ */

export function useEvents(query: EventQuery) {
  return useQuery({
    queryKey: ['events', query],
    queryFn: () => listEvents(query),
    staleTime: 5_000,
  })
}

/* mitre ------------------------------------------------------------------- */

export function useTactics() {
  return useQuery({ queryKey: ['tactics'], queryFn: listTactics, staleTime: 60_000 })
}

export function useTechniques(includeSubtechniques = false) {
  return useQuery({
    queryKey: ['techniques', includeSubtechniques],
    queryFn: () => listTechniques({ includeSubtechniques }),
    staleTime: 60_000,
  })
}

export function useCoverage() {
  return useQuery({ queryKey: ['coverage'], queryFn: () => getCoverage({}), staleTime: 30_000 })
}

/* scenarios --------------------------------------------------------------- */

export function useScenarios() {
  return useQuery({ queryKey: ['scenarios'], queryFn: getScenarioCatalog, staleTime: 30_000 })
}

/* evaluation -------------------------------------------------------------- */

export function useEvaluationRuns() {
  return useQuery({ queryKey: ['evaluation-runs'], queryFn: () => listEvaluationRuns(10), staleTime: 5_000 })
}

export function useStageComparison(runId?: number) {
  return useQuery({
    queryKey: ['stages', runId ?? 'latest'],
    queryFn: () => getStageComparison(runId),
    staleTime: 5_000,
  })
}

export const evaluationMutations = {
  run: runEvaluation,
  confirm: confirmChain,
  dismiss: dismissChain,
  feedback: postFeedback,
}
export type { AcrGraphOut, EvaluationRunRequest }
