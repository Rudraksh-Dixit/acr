import { useKillChain } from '../../lib/killchain'

export function KillChainStrip({
  covered,
  compact = false,
}: {
  covered?: number[] | null
  compact?: boolean
}) {
  const { stages } = useKillChain()
  if (stages.length === 0) return null
  const set = new Set(covered ?? [])
  return (
    <div className="flex items-end gap-1" role="list" aria-label="Kill chain stage coverage">
      {stages.map((name, i) => {
        const stage = i + 1
        const on = set.has(stage)
        return (
          <div
            key={name}
            role="listitem"
            title={`Stage ${stage} \u2014 ${name}${on ? ' (covered by chain)' : ' (not covered)'}`}
            className={`flex flex-col items-center gap-0.5 ${compact ? '' : 'min-w-0 flex-1'}`}
          >
            <div
              className={`flex h-4 min-w-4 items-center justify-center rounded-sm border px-1 text-[9px] mono ${
                on ? 'border-fg/70 bg-fg/10 text-fg' : 'border-line text-fg-faint opacity-60'
              }`}
            >
              {stage}
            </div>
            {!compact ? (
              <span className="w-full truncate text-center text-[8px] tracking-[0.06em] text-fg-faint uppercase">
                {name}
              </span>
            ) : null}
          </div>
        )
      })}
    </div>
  )
}
