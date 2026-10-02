/** Builds the visual model of a backend GraphOut:
 *  - positions along a temporal spine (events in timestamp order)
 *  - entity lanes above/below the spine, anchored to their events
 *  - a reveal order used by attack replay (purely derived from timestamps
 *    and backend edges — no fabricated relationships) */
import type { AcrGraphEdge, AcrGraphOut, AcrGraphNode } from '../api/types'

export const EVENT_SPACING = 250

const LANE_OFFSET: Record<string, number> = {
  TECHNIQUE: -330,
  PROCESS: -170,
  IP: -330,
  DOMAIN: -470,
  FILE: 170,
  HOST: 330,
  USER: 470,
}

export interface PositionedNode extends AcrGraphNode {
  x: number
  y: number
  reveal: number
}

export interface PositionedEdge extends AcrGraphEdge {
  reveal: number
}

export interface GraphModel {
  nodes: PositionedNode[]
  edges: PositionedEdge[]
  spineIds: string[]
  neighbors: Map<string, Set<string>>
  incidentEdges: Map<string, Set<string>>
  maxReveal: number
}

function sortByTime(nodes: AcrGraphNode[]): AcrGraphNode[] {
  return [...nodes].sort((a, b) => {
    const ta = a.timestamp ? Date.parse(a.timestamp) : Number.MAX_SAFE_INTEGER
    const tb = b.timestamp ? Date.parse(b.timestamp) : Number.MAX_SAFE_INTEGER
    if (ta !== tb) return ta - tb
    return a.id.localeCompare(b.id)
  })
}

export function buildGraphModel(graph: Pick<AcrGraphOut, 'nodes' | 'edges'> | null | undefined): GraphModel {
  const nodes: AcrGraphNode[] = graph?.nodes ?? []
  const edges: AcrGraphEdge[] = graph?.edges ?? []

  const byId = new Map(nodes.map((n) => [n.id, n]))
  const pos = new Map<string, PositionedNode>()

  // 1. temporal spine: EVENT nodes, strictly ordered by timestamp
  const events = sortByTime(nodes.filter((n) => n.type === 'EVENT'))
  const spineIds = events.map((n) => n.id)
  events.forEach((n, i) => {
    pos.set(n.id, { ...n, x: i * EVENT_SPACING, y: 0, reveal: i })
  })

  // 2. propagate placement to entities along backend edges (BFS-style fixpoint)
  const incident = new Map<string, AcrGraphEdge[]>()
  for (const e of edges) {
    if (!byId.has(e.source) || !byId.has(e.target)) continue
    if (!incident.has(e.source)) incident.set(e.source, [])
    if (!incident.has(e.target)) incident.set(e.target, [])
    incident.get(e.source)!.push(e)
    incident.get(e.target)!.push(e)
  }

  let changed = true
  let guard = 0
  while (changed && guard++ <= nodes.length + 2) {
    changed = false
    for (const e of edges) {
      const a = pos.get(e.source)
      const b = pos.get(e.target)
      if (a && !b) {
        pos.set(e.target, { ...(byId.get(e.target) as AcrGraphNode), x: a.x, y: 0, reveal: a.reveal })
        changed = true
      } else if (!a && b) {
        pos.set(e.source, { ...(byId.get(e.source) as AcrGraphNode), x: b.x, y: 0, reveal: b.reveal })
        changed = true
      } else if (a && b) {
        if (b.reveal > a.reveal) {
          b.reveal = a.reveal
          changed = true
        }
        if (a.reveal > b.reveal) {
          a.reveal = b.reveal
          changed = true
        }
      }
    }
  }

  // nodes unreachable from any event: park after the spine
  let tail = events.length * EVENT_SPACING
  for (const n of nodes) {
    if (!pos.has(n.id)) {
      pos.set(n.id, { ...n, x: tail, y: 0, reveal: events.length })
      tail += EVENT_SPACING / 2
      changed = true
    }
  }
  void changed

  // 3. entity lanes with simple collision stacking
  const lanes = new Map<string, Array<{ node: PositionedNode; x: number }>>()
  for (const p of pos.values()) {
    if (p.type === 'EVENT') continue
    const lane = p.type
    if (!lanes.has(lane)) lanes.set(lane, [])
    lanes.get(lane)!.push({ node: p, x: p.x })
  }
  for (const [lane, members] of lanes) {
    const base = LANE_OFFSET[lane] ?? -170
    const dir = base < 0 ? -1 : 1
    members.sort((a, b) => a.x - b.x || a.node.id.localeCompare(b.node.id))
    let lastX = Number.NEGATIVE_INFINITY
    let stack = 0
    for (const m of members) {
      if (m.x - lastX < 175) stack += 1
      else stack = 0
      lastX = m.x
      m.node.y = base + dir * stack * 74
    }
  }

  // 4. edge reveal = when both endpoints are visible
  const positionedEdges: PositionedEdge[] = edges
    .filter((e) => pos.has(e.source) && pos.has(e.target))
    .map((e) => ({
      ...e,
      reveal: Math.max(pos.get(e.source)!.reveal, pos.get(e.target)!.reveal),
    }))

  // 5. adjacency for hover / selection highlighting
  const neighbors = new Map<string, Set<string>>()
  const incidentEdges = new Map<string, Set<string>>()
  for (const n of nodes) {
    neighbors.set(n.id, new Set())
    incidentEdges.set(n.id, new Set())
  }
  for (const e of positionedEdges) {
    neighbors.get(e.source)?.add(e.target)
    neighbors.get(e.target)?.add(e.source)
    incidentEdges.get(e.source)?.add(e.id)
    incidentEdges.get(e.target)?.add(e.id)
  }

  const maxReveal = Math.max(events.length, ...[...pos.values()].map((p) => p.reveal), 0)

  return {
    nodes: [...pos.values()],
    edges: positionedEdges,
    spineIds,
    neighbors,
    incidentEdges,
    maxReveal,
  }
}
