'use client'

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import cytoscape from 'cytoscape'
// @ts-ignore — fcose has no bundled types for register()
import fcose from 'cytoscape-fcose'
import { useTopologyGraph } from '@/hooks/useAssets'
import { useRouter } from 'next/navigation'
import { cn } from '@/lib/utils'
import { ArrowRight, Eye, Filter, GitBranch, Maximize2, Network, Radio, RefreshCw, Split, Waypoints, Wifi, ZoomIn, ZoomOut } from 'lucide-react'

if (globalThis.window !== undefined) {
  cytoscape.use(fcose)
}

const DEVICE_COLORS: Record<string, string> = {
  router: '#f59e0b',
  switch: '#8b5cf6',
  access_point: '#06b6d4',
  firewall: '#ef4444',
  server: '#3b82f6',
  workstation: '#6366f1',
  nas: '#0ea5e9',
  printer: '#84cc16',
  ip_camera: '#ec4899',
  smart_tv: '#f97316',
  game_console: '#14b8a6',
  iot_device: '#10b981',
  voip: '#14b8a6',
  unknown: '#71717a',
}

const STATUS_BORDER: Record<string, string> = {
  online: '#10b981',
  offline: '#ef4444',
  unknown: '#71717a',
}

const RELATIONSHIP_COLORS: Record<string, string> = {
  gateway_for: '#f59e0b',
  wireless_ap_for: '#06b6d4',
  neighbor_l2: '#8b5cf6',
  arp_seen_by: '#71717a',
  uplink: '#2563eb',
}

const DEVICE_FILTER_OPTIONS = [
  { value: 'all', label: 'All types' },
  { value: 'router', label: 'Routers' },
  { value: 'switch', label: 'Switches' },
  { value: 'access_point', label: 'Access Points' },
  { value: 'server', label: 'Servers' },
  { value: 'workstation', label: 'Workstations' },
  { value: 'iot_device', label: 'IoT' },
  { value: 'unknown', label: 'Unknown' },
]

function deviceColor(deviceType: string | null): string {
  return DEVICE_COLORS[deviceType ?? 'unknown'] ?? DEVICE_COLORS.unknown
}

function relationshipColor(relationshipType: string | undefined): string {
  return RELATIONSHIP_COLORS[relationshipType ?? ''] ?? '#94a3b8'
}

function edgeLineStyle(observed: boolean | undefined): 'solid' | 'dashed' {
  return observed === false ? 'dashed' : 'solid'
}

function nodeShape(role: string | null | undefined): string {
  if (role === 'gateway') return 'hexagon'
  if (role === 'switch') return 'round-rectangle'
  if (role === 'access_point') return 'diamond'
  if (role === 'gateway_candidate' || role === 'infrastructure') return 'round-rectangle'
  return 'ellipse'
}

function tierRow(tier: string | null | undefined): number {
  if (tier === 'gateway') return 110
  if (tier === 'distribution') return 290
  return 500
}

type SelectedGraphItem =
  | { kind: 'node'; data: Record<string, unknown> }
  | { kind: 'edge'; data: Record<string, unknown> }

export function TopologyMap() {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const router = useRouter()

  const { data: graph, isLoading, isError, refetch } = useTopologyGraph()

  const [darkMode, setDarkMode] = useState(() =>
    typeof document !== 'undefined' ? document.documentElement.classList.contains('dark') : false,
  )
  const [filter, setFilter] = useState('all')
  const [segmentFilter, setSegmentFilter] = useState('all')
  const [layoutMode, setLayoutMode] = useState<'overview' | 'raw'>('overview')
  const [showObservedOnly, setShowObservedOnly] = useState(false)
  const [selectedItem, setSelectedItem] = useState<SelectedGraphItem | null>(null)

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setDarkMode(document.documentElement.classList.contains('dark'))
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  const bgColor = darkMode ? '#18181b' : '#fafafa'
  const edgeColor = darkMode ? '#3f3f46' : '#d4d4d8'
  const labelColor = darkMode ? '#e4e4e7' : '#27272a'

  const filteredGraph = useMemo(() => {
    if (!graph) {
      return { nodes: [], edges: [], segments: [] as NonNullable<typeof graph>['segments'] }
    }

    const nodes = graph.nodes.filter((node) => {
      const matchesDevice = filter === 'all' || node.data.device_type === filter
      const matchesSegment = segmentFilter === 'all' || String(node.data.segment_id ?? '') === segmentFilter
      return matchesDevice && matchesSegment
    })
    const visibleIds = new Set(nodes.map((node) => node.data.id))
    const edges = graph.edges.filter((edge) => {
      const visible = visibleIds.has(edge.data.source) && visibleIds.has(edge.data.target)
      const matchesSegment = segmentFilter === 'all' || String(edge.data.segment_id ?? '') === segmentFilter
      const matchesObserved = !showObservedOnly || edge.data.observed !== false
      return visible && matchesSegment && matchesObserved
    })
    const visibleSegmentIds = new Set(nodes.map((node) => String(node.data.segment_id ?? '')))
    const segments = (graph.segments ?? []).filter((segment) => segmentFilter === 'all' ? visibleSegmentIds.has(String(segment.id)) : String(segment.id) === segmentFilter)
    return { nodes, edges, segments }
  }, [graph, filter, segmentFilter, showObservedOnly])

  const elements = useMemo(() => {
    const segmentOrder = new Map(filteredGraph.segments.map((segment, index) => [segment.id, index]))
    const tierOffsets = new Map<string, number>()

    const nodes = filteredGraph.nodes.map((node) => {
      const segmentId = node.data.segment_id ?? -1
      const segmentColumn = segmentOrder.get(segmentId) ?? 0
      const tier = node.data.layout_tier ?? 'endpoint'
      const tierKey = `${segmentId}:${tier}`
      const nextOffset = tierOffsets.get(tierKey) ?? 0
      tierOffsets.set(tierKey, nextOffset + 1)
      const x = 180 + segmentColumn * 360 + nextOffset * 130
      const y = tierRow(tier) + (nextOffset % 2) * 22

      return {
        data: {
          id: node.data.id,
          label: node.data.label || node.data.ip,
          ip: node.data.ip,
          vendor: node.data.vendor,
          os: node.data.os,
          status: node.data.status,
          device_type: node.data.device_type,
          topology_role: node.data.topology_role,
          topology_confidence: node.data.topology_confidence,
          is_gateway: node.data.is_gateway,
          segment_id: node.data.segment_id,
          segment_cidr: node.data.segment_cidr,
          color: deviceColor(node.data.device_type),
          border: STATUS_BORDER[node.data.status] ?? STATUS_BORDER.unknown,
          shape: nodeShape(node.data.topology_role),
        },
        position: { x, y },
      }
    })

    const edges = filteredGraph.edges.map((edge) => ({
      data: {
        id: edge.data.id,
        source: edge.data.source,
        target: edge.data.target,
        link_type: edge.data.link_type,
        relationship_type: edge.data.relationship_type,
        observed: edge.data.observed ?? true,
        confidence: edge.data.confidence ?? 0.5,
        lineStyle: edgeLineStyle(edge.data.observed),
        color: relationshipColor(edge.data.relationship_type),
        source_kind: edge.data.source_kind,
        segment_id: edge.data.segment_id,
        local_interface: edge.data.local_interface,
        remote_interface: edge.data.remote_interface,
        ssid: edge.data.ssid,
        evidence: edge.data.evidence,
      },
    }))

    return [...nodes, ...edges]
  }, [filteredGraph])

  useEffect(() => {
    if (!containerRef.current || !graph) return

    if (cyRef.current) {
      cyRef.current.destroy()
      cyRef.current = null
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'border-color': 'data(border)',
            'border-width': 3,
            'shape': 'data(shape)' as any,
            'label': 'data(label)',
            'color': labelColor,
            'font-size': 11,
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-max-width': '110px',
            'text-overflow-wrap': 'anywhere',
            'width': 46,
            'height': 46,
          },
        },
        {
          selector: 'node[is_gateway = 1], node[is_gateway = true]',
          style: {
            'width': 56,
            'height': 56,
            'border-width': 4,
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 'mapData(confidence, 0, 1, 1.5, 4)' as any,
            'line-color': 'data(color)',
            'target-arrow-color': 'data(color)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 'mapData(confidence, 0, 1, 0.3, 0.95)' as any,
            'line-style': 'data(lineStyle)' as any,
          },
        },
        {
          selector: 'node:selected, edge:selected',
          style: {
            'overlay-color': '#0ea5e9',
            'overlay-opacity': 0.15,
            'overlay-padding': 6,
          },
        },
      ],
      layout: layoutMode === 'overview'
        ? { name: 'preset', fit: true, padding: 60 }
        : {
            name: 'fcose',
            quality: 'default',
            randomize: true,
            animate: true,
            animationDuration: 600,
            fit: true,
            padding: 40,
            nodeSeparation: 100,
            idealEdgeLength: 140,
          } as any,
      wheelSensitivity: 0.3,
    })

    cy.on('tap', 'node', (evt) => {
      setSelectedItem({ kind: 'node', data: evt.target.data() as Record<string, unknown> })
    })
    cy.on('tap', 'edge', (evt) => {
      setSelectedItem({ kind: 'edge', data: evt.target.data() as Record<string, unknown> })
    })
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedItem(null)
      }
    })

    cyRef.current = cy
    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [elements, graph, layoutMode, labelColor])

  function handleZoomIn() { cyRef.current?.zoom(cyRef.current.zoom() * 1.2) }
  function handleZoomOut() { cyRef.current?.zoom(cyRef.current.zoom() * 0.8) }
  function handleFit() { cyRef.current?.fit(undefined, 40) }
  function handleRefresh() { refetch() }

  if (isError) {
    return <div className="flex items-center justify-center h-full text-zinc-400"><p>Failed to load topology graph.</p></div>
  }

  if (isLoading) {
    return <div className="flex items-center justify-center h-full"><RefreshCw className="w-6 h-6 text-zinc-400 animate-spin" /></div>
  }

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 text-zinc-400">
        <p className="text-sm">No topology data yet.</p>
        <p className="text-xs">Run a scan to build the network map.</p>
      </div>
    )
  }

  const observedEdgeCount = filteredGraph.edges.filter((edge) => edge.data.observed !== false).length
  const inferredEdgeCount = filteredGraph.edges.length - observedEdgeCount

  return (
    <div className="grid h-full min-h-[720px] grid-cols-1 xl:grid-cols-[minmax(0,1fr)_320px] gap-4">
      <div className="relative min-h-[720px] overflow-hidden rounded-2xl border border-gray-200 dark:border-zinc-800">
        <div
          ref={containerRef}
          id="topology-canvas"
          className="h-full w-full"
          style={{ background: bgColor }}
        />

        <div className="absolute left-3 top-3 right-3 flex flex-wrap items-center gap-2 rounded-xl border border-gray-200 bg-white/95 px-3 py-2 text-xs shadow-sm backdrop-blur dark:border-zinc-700 dark:bg-zinc-900/95">
          <div className="inline-flex items-center gap-1.5 text-zinc-500">
            <Network className="h-3.5 w-3.5" />
            {filteredGraph.nodes.length} nodes
          </div>
          <div className="inline-flex items-center gap-1.5 text-zinc-500">
            <GitBranch className="h-3.5 w-3.5" />
            {observedEdgeCount} observed
          </div>
          <div className="inline-flex items-center gap-1.5 text-zinc-500">
            <Waypoints className="h-3.5 w-3.5" />
            {inferredEdgeCount} inferred
          </div>
          <div className="inline-flex items-center gap-1.5 text-zinc-500">
            <Split className="h-3.5 w-3.5" />
            {filteredGraph.segments.length} segments
          </div>
        </div>

        <div className="absolute left-3 top-16 flex flex-wrap gap-2">
          <select
            value={layoutMode}
            onChange={(event) => setLayoutMode(event.target.value as 'overview' | 'raw')}
            className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900"
          >
            <option value="overview">Overview layout</option>
            <option value="raw">Raw graph</option>
          </select>
          <select
            value={segmentFilter}
            onChange={(event) => setSegmentFilter(event.target.value)}
            className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900"
          >
            <option value="all">All segments</option>
            {(graph.segments ?? []).map((segment) => (
              <option key={segment.id} value={String(segment.id)}>{segment.label}</option>
            ))}
          </select>
          <div className="relative">
            <Filter className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-400" />
            <select
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              className="appearance-none rounded-lg border border-gray-200 bg-white pl-7 pr-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900"
            >
              {DEVICE_FILTER_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </div>
          <label className="inline-flex items-center gap-2 rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900">
            <input
              type="checkbox"
              checked={showObservedOnly}
              onChange={(event) => setShowObservedOnly(event.target.checked)}
            />
            Observed only
          </label>
        </div>

        <div className="absolute bottom-3 left-3 flex flex-wrap gap-2 rounded-xl border border-gray-200 bg-white/95 px-3 py-2 text-[11px] shadow-sm backdrop-blur dark:border-zinc-700 dark:bg-zinc-900/95">
          <LegendSwatch color="#f59e0b" label="Gateway" />
          <LegendSwatch color="#8b5cf6" label="LLDP/CDP" />
          <LegendSwatch color="#06b6d4" label="Wireless" />
          <LegendSwatch color="#71717a" label="Inferred/ARP" dashed />
        </div>

        <div className="absolute bottom-3 right-3 flex flex-col gap-1.5">
          <MapControlButton title="Zoom in" onClick={handleZoomIn}><ZoomIn className="w-4 h-4" /></MapControlButton>
          <MapControlButton title="Zoom out" onClick={handleZoomOut}><ZoomOut className="w-4 h-4" /></MapControlButton>
          <MapControlButton title="Fit" onClick={handleFit}><Maximize2 className="w-4 h-4" /></MapControlButton>
          <MapControlButton title="Refresh" onClick={handleRefresh}><RefreshCw className="w-4 h-4" /></MapControlButton>
        </div>
      </div>

      <aside className="rounded-2xl border border-gray-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
        <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">Topology Detail</h3>
        <p className="mt-1 text-xs text-zinc-500">
          Select a node or edge to inspect why Argus placed it here.
        </p>

        {!selectedItem ? (
          <div className="mt-4 space-y-4">
            <div className="rounded-xl border border-gray-200 p-3 dark:border-zinc-800">
              <p className="text-xs font-medium text-zinc-500">Segments</p>
              <div className="mt-2 space-y-2">
                {(filteredGraph.segments.length > 0 ? filteredGraph.segments : (graph.segments ?? [])).map((segment) => (
                  <div key={segment.id} className="rounded-lg bg-zinc-50 px-3 py-2 text-xs dark:bg-zinc-900">
                    <p className="font-medium text-zinc-900 dark:text-zinc-100">{segment.label}</p>
                    <p className="text-zinc-500">gateway: {segment.gateway_asset_id ? segment.gateway_asset_id.slice(0, 8) : 'unresolved'}</p>
                  </div>
                ))}
              </div>
            </div>
            <div className="rounded-xl border border-gray-200 p-3 dark:border-zinc-800">
              <p className="text-xs font-medium text-zinc-500">Layout Modes</p>
              <p className="mt-2 text-xs text-zinc-500">
                Overview uses segment columns with gateway, distribution, and endpoint tiers. Raw graph uses force layout for debugging unexpected relationships.
              </p>
            </div>
          </div>
        ) : selectedItem.kind === 'node' ? (
          <NodeDetailPanel
            data={selectedItem.data}
            onOpenAsset={() => router.push(`/assets/${selectedItem.data.id}`)}
          />
        ) : (
          <EdgeDetailPanel data={selectedItem.data} />
        )}
      </aside>
    </div>
  )
}

function LegendSwatch({ color, label, dashed = false }: Readonly<{ color: string; label: string; dashed?: boolean }>) {
  return (
    <div className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-400">
      <span className={cn('inline-block w-5 border-t-2', dashed && 'border-dashed')} style={{ borderColor: color }} />
      {label}
    </div>
  )
}

function NodeDetailPanel({
  data,
  onOpenAsset,
}: Readonly<{ data: Record<string, unknown>; onOpenAsset: () => void }>) {
  return (
    <div className="mt-4 space-y-4">
      <div>
        <p className="text-base font-semibold text-zinc-900 dark:text-white">{String(data.label ?? data.ip ?? 'Asset')}</p>
        <p className="text-xs text-zinc-500">{String(data.ip ?? '')}</p>
      </div>
      <dl className="space-y-2 text-sm">
        <DetailRow label="Role" value={String(data.topology_role ?? 'unknown')} />
        <DetailRow label="Device type" value={String(data.device_type ?? 'unknown')} />
        <DetailRow label="Segment" value={String(data.segment_cidr ?? 'unassigned')} />
        <DetailRow label="Status" value={String(data.status ?? 'unknown')} />
        <DetailRow label="Confidence" value={typeof data.topology_confidence === 'number' ? `${Math.round(Number(data.topology_confidence) * 100)}%` : '—'} />
        <DetailRow label="Vendor" value={String(data.vendor ?? '—')} />
        <DetailRow label="OS" value={String(data.os ?? '—')} />
      </dl>
      <button
        type="button"
        onClick={onOpenAsset}
        className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-3 py-2 text-sm text-white"
      >
        <ArrowRight className="h-4 w-4" />
        Open asset
      </button>
    </div>
  )
}

function EdgeDetailPanel({ data }: Readonly<{ data: Record<string, unknown> }>) {
  const evidence = (data.evidence && typeof data.evidence === 'object' ? data.evidence : null) as Record<string, unknown> | null

  return (
    <div className="mt-4 space-y-4">
      <div>
        <p className="text-base font-semibold text-zinc-900 dark:text-white">{String(data.relationship_type ?? data.link_type ?? 'Link')}</p>
        <p className="text-xs text-zinc-500">
          {String(data.source ?? '').slice(0, 8)} → {String(data.target ?? '').slice(0, 8)}
        </p>
      </div>
      <dl className="space-y-2 text-sm">
        <DetailRow label="Observed" value={data.observed === false ? 'No' : 'Yes'} />
        <DetailRow label="Confidence" value={typeof data.confidence === 'number' ? `${Math.round(Number(data.confidence) * 100)}%` : '—'} />
        <DetailRow label="Source" value={String(data.source_kind ?? '—')} />
        <DetailRow label="SSID" value={String(data.ssid ?? '—')} />
        <DetailRow label="Local interface" value={String(data.local_interface ?? '—')} />
        <DetailRow label="Remote interface" value={String(data.remote_interface ?? '—')} />
      </dl>
      {evidence && (
        <div className="rounded-xl border border-gray-200 bg-zinc-50 p-3 text-xs dark:border-zinc-800 dark:bg-zinc-900">
          <p className="mb-2 font-medium text-zinc-700 dark:text-zinc-300">Evidence</p>
          <pre className="overflow-x-auto whitespace-pre-wrap text-[11px] text-zinc-500">
            {JSON.stringify(evidence, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

function DetailRow({ label, value }: Readonly<{ label: string; value: string }>) {
  return (
    <div className="flex items-start justify-between gap-3">
      <dt className="text-zinc-500">{label}</dt>
      <dd className="text-right text-zinc-900 dark:text-zinc-100 break-all">{value}</dd>
    </div>
  )
}

function MapControlButton({
  title,
  onClick,
  children,
}: Readonly<{ title: string; onClick: () => void; children: ReactNode }>) {
  return (
    <button
      onClick={onClick}
      title={title}
      className={cn(
        'w-8 h-8 flex items-center justify-center rounded-lg text-zinc-600 dark:text-zinc-300',
        'bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-700',
        'hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors shadow-sm',
      )}
    >
      {children}
    </button>
  )
}
