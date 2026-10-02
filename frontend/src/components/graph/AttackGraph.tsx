import { Background, Controls, Handle, Position, ReactFlow, ReactFlowProvider, type Edge, type Node, type NodeProps } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { useMemo } from 'react'
import type { GraphModel, PositionedNode } from '../../lib/graph'
import { fmtClock, severityColor } from '../../lib/format'

export interface GraphNodeData extends Record<string, unknown> {
  node: PositionedNode
}

type AcrNode = Node<GraphNodeData>

function SeverityPip({ severity }: { severity?: string | null }) {
  if (!severity || severity === 'INFO') return null
  return (
    <span
      className="inline-block h-1.5 w-1.5 shrink-0 rounded-full"
      style={{ background: severityColor[severity] ?? 'var(--color-normal)' }}
    />
  )
}

function EntityNode({ data }: NodeProps<AcrNode>) {
  const n = data.node
  const isEvent = n.type === 'EVENT'

  const typeColor: Record<string, string> = {
    TECHNIQUE: 'var(--color-inferred)',
    HOST: 'var(--color-fg-muted)',
    PROCESS: 'var(--color-fg-muted)',
    IP: 'var(--color-warm)',
    DOMAIN: 'var(--color-warm)',
    FILE: 'var(--color-fg-muted)',
    USER: 'var(--color-fg-muted)',
    EVENT: 'var(--color-fg)',
  }

  if (isEvent) {
    return (
      <div className="entity-chip flex min-w-[150px] items-center gap-2 px-2.5 py-1.5" data-kind="event">
        <SeverityPip severity={n.severity} />
        <span className="text-[10px] text-fg-faint mono">{fmtClock(n.timestamp)}</span>
        <span className="text-[11px] font-medium text-fg">{n.label ?? n.event_type}</span>
        <Handle type="target" position={Position.Left} />
        <Handle type="target" position={Position.Top} />
        <Handle type="source" position={Position.Right} />
        <Handle type="source" position={Position.Bottom} />
      </div>
    )
  }

  return (
    <div
      className="entity-chip flex max-w-[230px] flex-col gap-0.5 px-3 py-2"
      style={{ borderColor: `color-mix(in srgb, ${typeColor[n.type] ?? 'var(--color-line-strong)'} 35%, transparent)` }}
    >
      <span className="text-[8.5px] font-semibold tracking-[0.18em] uppercase" style={{ color: typeColor[n.type] }}>
        {n.type}
      </span>
      <span className="truncate text-[11.5px] text-fg mono" title={n.label ?? ''}>
        {n.label ?? n.value ?? ''}
      </span>
      <Handle type="target" position={Position.Left} />
      <Handle type="target" position={Position.Top} />
      <Handle type="source" position={Position.Right} />
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}

const nodeTypes = { entity: EntityNode }

const RELATION_STYLE: Record<string, { stroke: string; dash?: string; width: number }> = {
  PRECEDES: { stroke: 'rgb(255 255 255 / 0.5)', width: 1.4 },
  SPAWNED: { stroke: 'rgb(255 255 255 / 0.36)', width: 1.2 },
  CREATED: { stroke: 'rgb(255 255 255 / 0.36)', width: 1.2 },
  CONNECTED: { stroke: 'rgb(217 164 65 / 0.55)', width: 1.2 },
  AUTHENTICATED: { stroke: 'rgb(255 255 255 / 0.3)', dash: '4 4', width: 1 },
  MODIFIED: { stroke: 'rgb(255 255 255 / 0.3)', dash: '4 4', width: 1 },
  ASSOCIATED_WITH: { stroke: 'rgb(255 255 255 / 0.14)', width: 0.8 },
  RESOLVES_TO: { stroke: 'rgb(217 164 65 / 0.35)', width: 1 },
  QUERIED: { stroke: 'rgb(217 164 65 / 0.35)', width: 1 },
}

function GraphCanvas({
  model,
  focusId,
  onNodeClick,
  revealCutoff,
}: {
  model: GraphModel
  focusId: string | null
  onNodeClick: (nodeId: string | null) => void
  revealCutoff: number
}) {
  const neighborhood = useMemo(() => {
    if (!focusId) return null
    const set = new Set<string>([focusId])
    for (const n of model.neighbors.get(focusId) ?? []) set.add(n)
    return set
  }, [focusId, model])

  const { nodes, edges } = useMemo(() => {
    const visible = model.nodes.filter((n) => n.reveal <= revealCutoff)
    const visibleIds = new Set(visible.map((n) => n.id))

    const rfNodes: AcrNode[] = visible.map((n) => ({
      id: n.id,
      type: 'entity',
      position: { x: n.x, y: n.y },
      data: { node: n },
      className: neighborhood && !neighborhood.has(n.id) ? 'dimmed' : undefined,
      draggable: false,
      zIndex: n.type === 'EVENT' ? 2 : 1,
    }))

    const rfEdges: Edge[] = model.edges
      .filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target) && e.reveal <= revealCutoff)
      .map((e) => {
        const style = RELATION_STYLE[e.relation] ?? RELATION_STYLE.ASSOCIATED_WITH
        const active = focusId ? e.source === focusId || e.target === focusId : false
        const dim = neighborhood ? !(active) && !neighborhood.has(e.source) : false
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          className: dim ? 'dimmed' : undefined,
          style: {
            stroke: active ? 'rgb(255 255 255 / 0.85)' : style.stroke,
            strokeWidth: active ? 1.8 : style.width,
            strokeDasharray: style.dash,
            transition: 'stroke 200ms ease',
          },
          data: { active },
        } as Edge
      })

    return { nodes: rfNodes, edges: rfEdges }
  }, [model, neighborhood, revealCutoff, focusId])

  return (
    <div className="h-full w-full">
      <ReactFlowProvider>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => onNodeClick(node.id)}
          onPaneClick={() => onNodeClick(null)}
          minZoom={0.15}
          maxZoom={1.6}
          fitView
          fitViewOptions={{ padding: 0.18, maxZoom: 1.1 }}
          proOptions={{ hideAttribution: true }}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable
        >
          <Background color="rgb(255 255 255 / 0.05)" gap={28} size={1} />
          <Controls showInteractive={false} position="bottom-left" />
        </ReactFlow>
      </ReactFlowProvider>
    </div>
  )
}

export default function AttackGraph(props: {
  model: GraphModel
  focusId: string | null
  onNodeClick: (nodeId: string | null) => void
  revealCutoff?: number
}) {
  return <GraphCanvas {...props} revealCutoff={props.revealCutoff ?? Number.MAX_SAFE_INTEGER} />
}
