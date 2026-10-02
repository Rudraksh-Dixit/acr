import { http } from './client'
import type { ConfigOut, HealthOut, PipelineOut, StatsOut } from './types'

export function getHealth(): Promise<HealthOut> {
  return http.get<HealthOut>('/api/health')
}

export function getStats(): Promise<StatsOut> {
  return http.get<StatsOut>('/api/stats')
}

export function getConfig(): Promise<ConfigOut> {
  return http.get<ConfigOut>('/api/config')
}

export function getPipeline(): Promise<PipelineOut> {
  return http.get<PipelineOut>('/api/pipeline')
}
