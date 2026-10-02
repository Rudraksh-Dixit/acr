import { http } from './client'
import type {
  EvaluationOut,
  EvaluationRunListOut,
  EvaluationRunRequest,
  EvaluationRunSummary,
  StageComparisonOut,
} from './types'

export function runEvaluation(body: Partial<EvaluationRunRequest> = {}): Promise<EvaluationOut> {
  const payload: EvaluationRunRequest = { seed: 42, persist: true, ...body }
  return http.post<EvaluationOut>('/api/evaluation/run', payload)
}

export function listEvaluationRuns(limit = 20, offset = 0): Promise<EvaluationRunListOut> {
  return http.get<EvaluationRunListOut>('/api/evaluation/runs', { limit, offset })
}

export function getEvaluationRun(runId: number): Promise<EvaluationRunSummary & Record<string, unknown>> {
  return http.get(`/api/evaluation/runs/${runId}`)
}

export function getStageComparison(runId?: number): Promise<StageComparisonOut> {
  return http.get<StageComparisonOut>('/api/evaluation/stages', { run_id: runId })
}
