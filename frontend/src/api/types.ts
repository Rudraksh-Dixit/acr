/** Graph payloads carry extra runtime fields beyond the generated minimal
 *  GraphNode/GraphEdge shapes (event metadata, edge detail). */
import type { components } from './schema'

type S = components['schemas']

export type AnalystFeedbackOut = S['AnalystFeedbackOut']
export type AttackStage = S['AttackStage']
export type ChainDetail = S['ChainDetail']
export type ChainListOut = S['ChainListOut']
export type ChainSummary = S['ChainSummary']
export type ConfidenceOut = S['ConfidenceOut']
export type ConfidenceReason = S['ConfidenceReason']
export type CoverageOut = S['CoverageOut']
export type CoverageTechnique = S['CoverageTechnique']
export type CoverageTactic = S['CoverageTactic']
export type DetectionOut = S['DetectionOut']
export type EntityLinkOut = S['EntityLinkOut']
export type EntityRefOut = S['EntityRefOut']
export type EvaluationOut = S['EvaluationOut']
export type EvaluationRunDetail = S['EvaluationRunDetail']
export type EvaluationRunListOut = S['EvaluationRunListOut']
export type EvaluationRunRequest = S['EvaluationRunRequest']
export type EvaluationRunSummary = S['EvaluationRunSummary']
export type EventDetailOut = S['EventDetailOut']
export type EventListOut = S['EventListOut']
export type EventOut = S['EventOut']
export type EvidenceBlock = S['EvidenceBlock']
export type EvidenceItem = S['EvidenceItem']
export type FeedbackComment = S['FeedbackComment']
export type FeedbackRequest = S['FeedbackRequest']
export type GraphEdge = S['GraphEdge']
export type GraphNode = S['GraphNode']
export type GraphOut = S['GraphOut']
export type IngestIssue = S['IngestIssue']
export type IngestReportOut = S['IngestReportOut']
export type IngestRequest = S['IngestRequest']
export type InvestigationOut = S['InvestigationOut']
export type MissingStep = S['MissingStep']
export type NetworkViewOut = S['NetworkViewOut']
export type ProcessTreeNode = S['ProcessTreeNode']
export type RiskFactor = S['RiskFactor']
export type RiskOut = S['RiskOut']
export type ScenarioCatalogItem = S['ScenarioCatalogItem']
export type ScenarioCatalogOut = S['ScenarioCatalogOut']
export type ScenarioGenerateItem = S['ScenarioGenerateItem']
export type ScenarioGenerateOut = S['ScenarioGenerateOut']
export type ScenarioGenerateRequest = S['ScenarioGenerateRequest']
export type ScenarioResetOut = S['ScenarioResetOut']
export type StageComparisonOut = S['StageComparisonOut']
export type TacticListOut = S['TacticListOut']
export type TacticOut = S['TacticOut']
export type TechniqueListOut = S['TechniqueListOut']
export type TechniqueOut = S['TechniqueOut']
export type TechniqueRef = S['TechniqueRef']
export type TimelineItem = S['TimelineItem']
export type TimelineOut = S['TimelineOut']

export interface AcrGraphNode extends GraphNode {
  event_id?: string | null
  event_type?: string | null
  timestamp?: string | null
  severity?: string | null
  host?: string | null
  user?: string | null
  process?: string | null
  command_line?: string | null
  technique_id?: string | null
  value?: string | null
}

export interface AcrGraphEdge extends GraphEdge {
  detail?: string
}

export interface AcrGraphOut {
  chain_id?: string | null
  nodes: AcrGraphNode[]
  edges: AcrGraphEdge[]
  relationships?: AcrGraphEdge[]
  metadata?: Record<string, unknown> | null
}

/** one network connection row from NetworkViewOut.connections */
export interface NetworkConnection {
  event_id?: string
  timestamp?: string | null
  source_ip?: string | null
  destination_ip?: string | null
  destination_port?: number | null
  protocol?: string | null
  process?: string | null
  host?: string | null
  severity?: string | null
}

export interface DnsQuery {
  event_id?: string
  timestamp?: string | null
  domain?: string
  query_name?: string
  destination_ip?: string | null
  process?: string | null
  host?: string | null
  [k: string]: unknown
}

/** network view with typed rows */
export interface NetworkView {
  connections?: NetworkConnection[] | null
  dns_queries?: DnsQuery[] | null
  external_destinations?: string[] | null
  graph?: Record<string, unknown> | null
  counts?: Record<string, number> | null
}

/** GET /api/health etc. */
export type Schemas = components['schemas']

/** GET /api/health */
export interface HealthOut {
  status: string
  app: string
  version: string
  database: string
  database_ok: boolean
  time: string
}

/** GET /api/stats */
export interface StatsOut {
  app: string
  version: string
  counts: {
    events: number
    detections: number
    chains: number
    attack_chains: number
    entities: number
    techniques: number
    evaluation_runs: number
  }
  events_by_severity: Record<string, number>
  chains_by_risk_level: Record<string, number>
  chains_by_status: Record<string, number>
  last_ingest: string | null
  last_reconstruction: string | null
}

/** GET /api/config */
export interface ConfigOut {
  app_name: string
  version: string
  time_windows: Record<string, number>
  weights: Record<string, number>
  min_edge_score: number
  min_chain_confidence: number
  attack_confidence_threshold: number
  attack_risk_threshold: number
  brute_force_failures: number
  brute_force_window: number
  max_upload_bytes: number
  max_events_per_ingest: number
  engine: string
  confidence_engine: string
  risk_engine: string
  summary_provider: string
}

/** GET /api/pipeline */
export interface PipelineOut {
  stages: Array<{
    stage: string
    description: string
    count: number | null
    last_run_at: string | null
    last_run_detail: Record<string, unknown> | null
  }>
  config: Record<string, unknown>
}
