import { http } from './client'
import type { CoverageOut, TacticListOut, TechniqueListOut, TechniqueOut } from './types'

export function listTactics(): Promise<TacticListOut> {
  return http.get<TacticListOut>('/api/mitre/tactics')
}

export function listTechniques(opts: { tactic?: string; includeSubtechniques?: boolean } = {}): Promise<TechniqueListOut> {
  return http.get<TechniqueListOut>('/api/mitre/techniques', {
    tactic: opts.tactic,
    include_subtechniques: opts.includeSubtechniques,
  })
}

export function getTechnique(techniqueId: string): Promise<TechniqueOut> {
  return http.get<TechniqueOut>(`/api/mitre/techniques/${encodeURIComponent(techniqueId)}`)
}

export function getCoverage(opts: { chainId?: string; scenarioId?: string } = {}): Promise<CoverageOut> {
  return http.get<CoverageOut>('/api/mitre/coverage', {
    chain_id: opts.chainId,
    scenario_id: opts.scenarioId,
  })
}
