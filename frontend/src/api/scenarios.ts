import { http } from './client'
import type { ScenarioCatalogOut, ScenarioGenerateOut, ScenarioGenerateRequest, ScenarioResetOut } from './types'

export function getScenarioCatalog(): Promise<ScenarioCatalogOut> {
  return http.get<ScenarioCatalogOut>('/api/scenarios')
}

export function generateScenarios(body: Partial<ScenarioGenerateRequest> = {}): Promise<ScenarioGenerateOut> {
  const payload: ScenarioGenerateRequest = {
    seed: 42,
    ingest: true,
    reconstruct: true,
    include_ground_truth: false,
    replace_duplicates: false,
    ...body,
  }
  return http.post<ScenarioGenerateOut>('/api/scenarios/generate', payload)
}

export function resetScenarios(opts: { confirm: boolean; reconstruct?: boolean } = { confirm: true }): Promise<ScenarioResetOut> {
  return http.post<ScenarioResetOut>('/api/scenarios/reset', {
    confirm: opts.confirm,
    reconstruct: opts.reconstruct ?? false,
  })
}
