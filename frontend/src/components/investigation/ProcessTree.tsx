import type { ProcessTreeNode } from '../../api/types'
import { severityColor } from '../../lib/format'
import { TechLabel } from '../ui/primitives'

function NodeRow({
  node,
  depth,
  onSelect,
}: {
  node: ProcessTreeNode
  depth: number
  onSelect: (eventId: string) => void
}) {
  const clickable = !!node.event_id
  return (
    <div>
      <button
        disabled={!clickable}
        onClick={() => node.event_id && onSelect(node.event_id)}
        className="group flex w-full items-start gap-3 border-b border-line/50 px-4 py-2 text-left transition-colors enabled:hover:bg-white/4 disabled:cursor-default"
        style={{ paddingLeft: 16 + depth * 26 }}
      >
        <span className="mt-1.5 shrink-0">
          <span
            className="block h-1.5 w-1.5 rounded-full"
            style={{ background: severityColor[node.severity ?? 'INFO'] ?? 'var(--color-normal)' }}
          />
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2">
            <span className="text-[12.5px] text-fg mono">{node.process_name}</span>
            {node.pid != null ? <span className="text-[10px] text-fg-faint mono">pid {node.pid}</span> : null}
            {node.technique_id ? (
              <span
                className="rounded-sm border px-1 py-px text-[9px] mono"
                style={{ color: 'var(--color-inferred)', borderColor: 'var(--color-inferred-deep)' }}
              >
                {node.technique_id}
              </span>
            ) : null}
          </span>
          {node.command_line ? (
            <span className="mt-0.5 block truncate text-[11px] text-fg-muted mono" title={node.command_line}>
              {node.command_line}
            </span>
          ) : null}
          <span className="mt-0.5 block text-[10px] text-fg-faint">
            {node.host ?? ''} {node.parent_process_name ? `· parent: ${node.parent_process_name}` : ''}
          </span>
        </span>
        {clickable ? (
          <span className="mt-1 shrink-0 text-[9px] tracking-[0.12em] text-fg-faint uppercase opacity-0 transition-opacity group-hover:opacity-100">
            focus
          </span>
        ) : null}
      </button>
      {(node.children ?? []).map((c) => (
        <NodeRow key={c.id} node={c} depth={depth + 1} onSelect={onSelect} />
      ))}
    </div>
  )
}

export default function ProcessTreeView({
  tree,
  onSelectEvent,
}: {
  tree: ProcessTreeNode[]
  onSelectEvent: (eventId: string) => void
}) {
  if (tree.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-[11px] tracking-[0.14em] text-fg-faint uppercase">No process lineage in this chain</p>
      </div>
    )
  }
  return (
    <div className="h-full overflow-y-auto">
      <div className="border-b border-line px-4 py-2">
        <TechLabel>Process lineage — parent to child, ordered by observation</TechLabel>
      </div>
      {tree.map((n) => (
        <NodeRow key={n.id} node={n} depth={0} onSelect={onSelectEvent} />
      ))}
    </div>
  )
}
