import { useConfig } from '../hooks/systemQueries'

export function useKillChain() {
  const config = useConfig()
  return {
    stages: config.data?.kill_chain?.stages ?? [],
    tacticToStage: config.data?.kill_chain?.tactic_to_stage ?? {},
    loaded: config.isSuccess,
  }
}

export function stageLabel(stages: string[], stage: number | null | undefined): string {
  if (stage == null) return ''
  const name = stages[stage - 1]
  return name ? `${stage} \u00b7 ${name}` : `Stage ${stage}`
}
