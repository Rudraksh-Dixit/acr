import { http } from './client'
import type {
  DatasetCatalogOut,
  DatasetRunListOut,
  DatasetRunOut,
  DatasetRunRequest,
} from './types'

export function listDatasets(): Promise<DatasetCatalogOut> {
  return http.get<DatasetCatalogOut>('/api/datasets')
}

export function runDataset(datasetId: string, body: Partial<DatasetRunRequest> = {}): Promise<DatasetRunOut> {
  const payload: DatasetRunRequest = {
    seed: 42,
    ingest: true,
    reconstruct: true,
    replace_existing: true,
    ...body,
  }
  return http.post<DatasetRunOut>(`/api/datasets/${encodeURIComponent(datasetId)}/run`, payload)
}

export function listDatasetRuns(limit = 20, offset = 0): Promise<DatasetRunListOut> {
  return http.get<DatasetRunListOut>('/api/datasets/runs', { limit, offset })
}
