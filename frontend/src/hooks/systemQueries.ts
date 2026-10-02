import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import { getConfig, getHealth, getPipeline, getStats } from '../api/system'
import type { ConfigOut, HealthOut, PipelineOut, StatsOut } from '../api/types'

export function useHealth(): UseQueryResult<HealthOut> {
  return useQuery({ queryKey: ['health'], queryFn: getHealth, refetchInterval: 15_000, staleTime: 10_000 })
}

export function useStats(): UseQueryResult<StatsOut> {
  return useQuery({ queryKey: ['stats'], queryFn: getStats, staleTime: 5_000 })
}

export function useConfig(): UseQueryResult<ConfigOut> {
  return useQuery({ queryKey: ['config'], queryFn: getConfig, staleTime: 60_000 })
}

export function usePipeline(): UseQueryResult<PipelineOut> {
  return useQuery({ queryKey: ['pipeline'], queryFn: getPipeline, staleTime: 10_000 })
}
