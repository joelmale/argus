'use client'

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import cytoscape from 'cytoscape'
// @ts-ignore — fcose has no bundled types for register()
import fcose from 'cytoscape-fcose'
import {
  useTopologyGraph,
  useNeighborhoodGraph,
  useCreateTopologyLink,
  useUpdateTopologyLink,
  useDeleteTopologyLink,
  useUpdateAsset,
} from '@/hooks/useAssets'
import { useRouter } from 'next/navigation'
import { cn } from '@/lib/utils'
import {
  ArrowRight,
  CheckCircle,
  ChevronDown,
  Eye,
  Filter,
  GitBranch,
  Link2,
  Maximize2,
  Network,
  Radio,
  RefreshCw,
  Search,
  Split,
  Unlink,
  Waypoints,
  XCircle,
  ZoomIn,
  ZoomOut,
} from 'lucide-react'
import type { TopologyNode } from '@/types'

if (globalThis.window !== undefined) {
  cytoscape.use(fcose)
}

// ─── constants ────────────────────────────────────────────────────────────────

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
  inferred_wireless: '#06b6d4',
  switch_port_for: '#2563eb',
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

const DEVICE_TYPES = [
  'router', 'switch', 'access_point', 'firewall', 'server',
  'workstation', 'nas', 'printer', 'ip_camera', 'smart_tv',
  'game_console', 'iot_device', 'voip', 'unknown',
]

const RELATIONSHIP_TYPES = [
  'neighbor_l2', 'wireless_ap_for', 'switch_port_for',
  'uplink', 'gateway_for', 'manual',
]

const LAYOUT_STORAGE_KEY = 'argus_topology_layout_v1'

// ─── helpers ──────────────────────────────────────────────────────────────────

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

function isInfrastructureNode(node: { data: Record<string, unknown> }): boolean {
  const role = String(node.data.topology_role ?? '')
  return Boolean(node.data.is_gateway)
    || role === 'gateway'
    || role === 'gateway_candidate'
    || role === 'switch'
    || role === 'access_point'
    || role === 'infrastructure'
}

function buildRadialPositions(
  nodes: Array<{ data: Record<string, unknown> }>,
  segments: Array<{ id: number; label: string }>,
) {
  const positions = new Map<string, { x: number; y: number }>()
  const segmentOrder = new Map(segments.map((s, i) => [s.id, i]))
  const bySegment = new Map<number, Array<{ data: Record<string, unknown> }>>()

  for (const node of nodes) {
    const segmentId = Number(node.data.segment_id ?? -1)
    const bucket = bySegment.get(segmentId) ?? []
    bucket.push(node)
    bySegment.set(segmentId, bucket)
  }

  const orderedSegments = Array.from(bySegment.entries()).sort((a, b) => {
    const aIdx = segmentOrder.get(a[0]) ?? Number.MAX_SAFE_INTEGER
    const bIdx = segmentOrder.get(b[0]) ?? Number.MAX_SAFE_INTEGER
    return aIdx - bIdx
  })

  for (const [index, [, segmentNodes]] of orderedSegments.entries()) {
    const column = index % 2
    const row = Math.floor(index / 2)
    const centerX = 260 + column * 540
    const centerY = 220 + row * 480
    const hubs = segmentNodes.filter(isInfrastructureNode)
    const endpoints = segmentNodes.filter((n) => !isInfrastructureNode(n))
    const hubRingRadius = hubs.length > 1 ? 90 : 0
    const endpointRingRadius = hubs.length > 1 ? 220 : 170

    if (hubs.length === 0 && segmentNodes.length > 0) {
      const [first, ...rest] = segmentNodes
      positions.set(String(first.data.id), { x: centerX, y: centerY })
      rest.forEach((node, i) => {
        const angle = (Math.PI * 2 * i) / Math.max(rest.length, 1)
        positions.set(String(node.data.id), {
          x: centerX + Math.cos(angle) * endpointRingRadius,
          y: centerY + Math.sin(angle) * endpointRingRadius,
        })
      })
      continue
    }

    hubs.forEach((node, i) => {
      const angle = hubRingRadius > 0 ? (Math.PI * 2 * i) / Math.max(hubs.length, 1) : 0
      positions.set(String(node.data.id), {
        x: centerX + Math.cos(angle) * hubRingRadius,
        y: centerY + Math.sin(angle) * hubRingRadius,
      })
    })

    endpoints.forEach((node, i) => {
      const angle = (Math.PI * 2 * i) / Math.max(endpoints.length, 1)
      positions.set(String(node.data.id), {
        x: centerX + Math.cos(angle) * endpointRingRadius,
        y: centerY + Math.sin(angle) * endpointRingRadius,
      })
    })
  }

  return positions
}

function loadSavedPositions(): Map<string, { x: number; y: number }> {
  try {
    const raw = globalThis.localStorage?.getItem(LAYOUT_STORAGE_KEY)
    if (!raw) return new Map()
    const obj = JSON.parse(raw) as Record<string, { x: number; y: number }>
    return new Map(Object.entries(obj))
  } catch {
    return new Map()
  }
}

function savePositions(cy: cytoscape.Core): void {
  try {
    const obj: Record<string, { x: number; y: number }> = {}
    cy.nodes().forEach((n) => {
      obj[n.id()] = n.position()
    })
    globalThis.localStorage?.setItem(LAYOUT_STORAGE_KEY, JSON.stringify(obj))
  } catch {
    // localStorage unavailable
  }
}

function clearSavedPositions(): void {
  try {
    globalThis.localStorage?.removeItem(LAYOUT_STORAGE_KEY)
  } catch {
    // noop
  }
}

// ─── types ────────────────────────────────────────────────────────────────────

type LayoutMode = 'radial' | 'overview' | 'hierarchy' | 'raw'

type SelectedGraphItem =
  | { kind: 'node'; data: Record<string, unknown> }
  | { kind: 'edge'; data: Record<string, unknown> }

// ─── main component ───────────────────────────────────────────────────────────

export function TopologyMap() {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const tooltipRef = useRef<HTMLDivElement>(null)
  const router = useRouter()

  const { data: graph, isLoading, isError, refetch } = useTopologyGraph()

  const [darkMode, setDarkMode] = useState(() =>
    typeof document !== 'undefined' ? document.documentElement.classList.contains('dark') : false,
  )
  const [filter, setFilter] = useState('all')
  const [segmentFilter, setSegmentFilter] = useState('all')
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('radial')
  const [dimInferred, setDimInferred] = useState(false)
  const [selectedItem, setSelectedItem] = useState<SelectedGraphItem | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [focusAssetId, setFocusAssetId] = useState<string | null>(null)
  const [linkDrawMode, setLinkDrawMode] = useState(false)
  const [linkDrawSource, setLinkDrawSource] = useState<string | null>(null)
  const [linkDrawRelType, setLinkDrawRelType] = useState('neighbor_l2')
  const [showLinkDialog, setShowLinkDialog] = useState(false)
  const [pendingLink, setPendingLink] = useState<{ source: string; target: string } | null>(null)
  const [layoutSaved, setLayoutSaved] = useState(false)

  const { data: neighborhoodGraph } = useNeighborhoodGraph(focusAssetId)
  const createLink = useCreateTopologyLink()
  const updateLink = useUpdateTopologyLink()
  const deleteLink = useDeleteTopologyLink()
  const updateAsset = useUpdateAsset()

  // Derive the active graph data (full or neighborhood focus)
  const activeGraph = focusAssetId && neighborhoodGraph ? neighborhoodGraph : graph

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setDarkMode(document.documentElement.classList.contains('dark'))
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  const bgColor = darkMode ? '#18181b' : '#fafafa'
  const labelColor = darkMode ? '#e4e4e7' : '#27272a'

  const filteredGraph = useMemo(() => {
    if (!activeGraph) {
      return { nodes: [], edges: [], segments: [] as NonNullable<typeof activeGraph>['segments'] }
    }
    const nodes = activeGraph.nodes.filter((node) => {
      const matchesDevice = filter === 'all' || node.data.device_type === filter
      const matchesSegment = segmentFilter === 'all' || String(node.data.segment_id ?? '') === segmentFilter
      const matchesSearch = !searchQuery || (
        String(node.data.label ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
        String(node.data.ip ?? '').includes(searchQuery)
      )
      return matchesDevice && matchesSegment && matchesSearch
    })
    const visibleIds = new Set(nodes.map((n) => n.data.id))
    const edges = activeGraph.edges.filter((edge) => {
      return visibleIds.has(edge.data.source) && visibleIds.has(edge.data.target) &&
        (segmentFilter === 'all' || String(edge.data.segment_id ?? '') === segmentFilter)
    })
    const visibleSegmentIds = new Set(nodes.map((n) => String(n.data.segment_id ?? '')))
    const segments = (activeGraph.segments ?? []).filter((s) =>
      segmentFilter === 'all' ? visibleSegmentIds.has(String(s.id)) : String(s.id) === segmentFilter,
    )
    return { nodes, edges, segments }
  }, [activeGraph, filter, segmentFilter, searchQuery])

  const elements = useMemo(() => {
    const segmentOrder = new Map(filteredGraph.segments.map((s, i) => [s.id, i]))
    const tierOffsets = new Map<string, number>()
    const savedPositions = loadSavedPositions()
    const radialPositions = buildRadialPositions(filteredGraph.nodes, filteredGraph.segments)

    const nodes = filteredGraph.nodes.map((node) => {
      const segmentId = node.data.segment_id ?? -1
      const segmentColumn = segmentOrder.get(segmentId) ?? 0
      const tier = node.data.layout_tier ?? 'endpoint'
      const tierKey = `${segmentId}:${tier}`
      const nextOffset = tierOffsets.get(tierKey) ?? 0
      tierOffsets.set(tierKey, nextOffset + 1)
      const saved = savedPositions.get(String(node.data.id))
      const radial = radialPositions.get(String(node.data.id))
      const x = saved?.x ?? radial?.x ?? (180 + segmentColumn * 360 + nextOffset * 130)
      const y = saved?.y ?? radial?.y ?? (tierRow(tier) + (nextOffset % 2) * 22)

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
          tier_hint: node.data.tier_hint,
          avg_latency_ms: node.data.avg_latency_ms,
          ttl_distance: node.data.ttl_distance,
        },
        position: { x, y },
      }
    })

    const edges = filteredGraph.edges.map((edge) => {
      const isInferred = edge.data.observed === false
      return {
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
          link_id: edge.data.link_id,
          // dim inferred edges when toggle is on
          edgeOpacity: dimInferred && isInferred ? 0.2 : Math.max(0.3, (edge.data.confidence ?? 0.5) * 0.95),
          edgeWidth: dimInferred && isInferred ? 1 : Math.max(1.5, (edge.data.confidence ?? 0.5) * 4),
        },
      }
    })

    return [...nodes, ...edges]
  }, [filteredGraph, dimInferred])

  // ── initial Cytoscape mount + destroy on layout mode change ──────────────────
  const initCytoscape = useCallback(() => {
    if (!containerRef.current || !activeGraph) return

    if (cyRef.current) {
      cyRef.current.destroy()
      cyRef.current = null
    }

    const layoutConfig = layoutMode === 'raw'
      ? {
          name: 'fcose',
          quality: 'default',
          randomize: true,
          animate: true,
          animationDuration: 600,
          fit: true,
          padding: 40,
          nodeSeparation: 100,
          idealEdgeLength: 140,
        } as any
      : layoutMode === 'hierarchy'
      ? {
          name: 'breadthfirst',
          directed: true,
          fit: true,
          padding: 60,
          spacingFactor: 1.4,
          avoidOverlap: true,
          animate: true,
          animationDuration: 500,
        }
      : { name: 'preset', fit: true, padding: layoutMode === 'overview' ? 60 : 80 }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: buildCytoscapeStyle(labelColor),
      layout: layoutConfig,
      wheelSensitivity: 0.3,
    })

    // Node click
    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data() as Record<string, unknown>
      if (linkDrawMode) {
        if (!linkDrawSource) {
          setLinkDrawSource(String(nodeData.id))
        } else if (linkDrawSource !== String(nodeData.id)) {
          setPendingLink({ source: linkDrawSource, target: String(nodeData.id) })
          setShowLinkDialog(true)
          setLinkDrawSource(null)
        }
        return
      }
      setSelectedItem({ kind: 'node', data: nodeData })
    })

    // Edge click
    cy.on('tap', 'edge', (evt) => {
      if (linkDrawMode) return
      setSelectedItem({ kind: 'edge', data: evt.target.data() as Record<string, unknown> })
    })

    // Canvas click — deselect
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedItem(null)
        if (linkDrawMode) setLinkDrawSource(null)
      }
    })

    // Hover tooltip on nodes
    cy.on('mouseover', 'node', (evt) => {
      const d = evt.target.data() as Record<string, unknown>
      const pos = evt.target.renderedPosition()
      const container = containerRef.current
      const tip = tooltipRef.current
      if (!tip || !container) return
      tip.innerHTML = `
        <div class="font-semibold text-zinc-900 dark:text-white">${String(d.label ?? d.ip ?? '')}</div>
        <div class="text-zinc-500">${String(d.ip ?? '')}</div>
        <div class="text-zinc-400 capitalize">${String(d.device_type ?? 'unknown').replace(/_/g, ' ')} · ${String(d.status ?? '')}</div>
        ${d.vendor ? `<div class="text-zinc-400">${String(d.vendor)}</div>` : ''}
      `
      const rect = container.getBoundingClientRect()
      tip.style.left = `${pos.x + rect.left + 12}px`
      tip.style.top = `${pos.y + rect.top - 8}px`
      tip.style.display = 'block'
    })
    cy.on('mouseout', 'node', () => {
      if (tooltipRef.current) tooltipRef.current.style.display = 'none'
    })

    // Hover tooltip on edges
    cy.on('mouseover', 'edge', (evt) => {
      const d = evt.target.data() as Record<string, unknown>
      const mpos = evt.renderedPosition
      const container = containerRef.current
      const tip = tooltipRef.current
      if (!tip || !container) return
      const relType = String(d.relationship_type ?? d.link_type ?? 'link').replace(/_/g, ' ')
      const confidence = typeof d.confidence === 'number' ? `${Math.round(Number(d.confidence) * 100)}%` : ''
      const observed = d.observed === false ? 'inferred' : 'observed'
      tip.innerHTML = `
        <div class="font-semibold text-zinc-900 dark:text-white capitalize">${relType}</div>
        <div class="text-zinc-400">${observed}${confidence ? ` · ${confidence}` : ''}</div>
        ${d.ssid ? `<div class="text-zinc-400">SSID: ${String(d.ssid)}</div>` : ''}
      `
      const rect = container.getBoundingClientRect()
      const pos = mpos()
      tip.style.left = `${pos.x + rect.left + 12}px`
      tip.style.top = `${pos.y + rect.top - 8}px`
      tip.style.display = 'block'
    })
    cy.on('mouseout', 'edge', () => {
      if (tooltipRef.current) tooltipRef.current.style.display = 'none'
    })

    cyRef.current = cy
    return () => {
      cy.destroy()
      cyRef.current = null
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeGraph, layoutMode, labelColor, linkDrawMode])

  // Re-init when layout mode or data source changes
  useEffect(() => {
    return initCytoscape()
  }, [initCytoscape])

  // Hot-swap elements when filter/search/dimming changes without destroying cy
  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return

    // Gather current element ids
    const currentIds = new Set(cy.elements().map((el) => el.id()))
    const nextIds = new Set(elements.map((el) => String(el.data.id)))

    // Remove stale
    cy.elements().filter((el) => !nextIds.has(el.id())).remove()

    // Add new
    const toAdd = elements.filter((el) => !currentIds.has(String(el.data.id)))
    if (toAdd.length > 0) cy.add(toAdd as any)

    // Update data on existing
    for (const el of elements) {
      const id = String(el.data.id)
      const existing = cy.getElementById(id)
      if (existing.length > 0) {
        existing.data(el.data)
        if ('position' in el && el.position) {
          const saved = loadSavedPositions().get(id)
          if (!saved) existing.position(el.position)
        }
      }
    }

    // Reapply styles (opacity/width may have changed due to dimInferred)
    cy.style(buildCytoscapeStyle(labelColor))
  // elements dep intentionally excludes graph/layoutMode to avoid double-trigger
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [elements, labelColor])

  // Spotlight search result
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !searchQuery) return
    cy.nodes().removeClass('highlighted')
    if (!searchQuery.trim()) return
    const q = searchQuery.toLowerCase()
    cy.nodes().filter((n) => {
      const label = String(n.data('label') ?? '').toLowerCase()
      const ip = String(n.data('ip') ?? '')
      return label.includes(q) || ip.includes(searchQuery)
    }).addClass('highlighted')
  }, [searchQuery])

  // Link draw mode cursor
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.style.cursor = linkDrawMode ? 'crosshair' : ''
    }
  }, [linkDrawMode])

  function handleZoomIn() { cyRef.current?.zoom(cyRef.current.zoom() * 1.2) }
  function handleZoomOut() { cyRef.current?.zoom(cyRef.current.zoom() * 0.8) }
  function handleFit() { cyRef.current?.fit(undefined, 40) }
  function handleRefresh() { refetch() }
  function handleSaveLayout() {
    if (cyRef.current) {
      savePositions(cyRef.current)
      setLayoutSaved(true)
      setTimeout(() => setLayoutSaved(false), 1500)
    }
  }
  function handleResetLayout() {
    clearSavedPositions()
    initCytoscape()
  }

  function handleConfirmLink(relType: string) {
    if (!pendingLink) return
    createLink.mutate({
      source_id: pendingLink.source,
      target_id: pendingLink.target,
      relationship_type: relType,
      observed: true,
      confidence: 1.0,
    })
    setShowLinkDialog(false)
    setPendingLink(null)
    setLinkDrawMode(false)
  }

  if (isError) {
    return (
      <div className="flex items-center justify-center h-full text-zinc-400">
        <p>Failed to load topology graph.</p>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <RefreshCw className="w-6 h-6 text-zinc-400 animate-spin" />
      </div>
    )
  }

  if (!activeGraph || activeGraph.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 text-zinc-400">
        <p className="text-sm">No topology data yet.</p>
        <p className="text-xs">Run a scan to build the network map.</p>
      </div>
    )
  }

  const observedEdgeCount = filteredGraph.edges.filter((e) => e.data.observed !== false).length
  const inferredEdgeCount = filteredGraph.edges.length - observedEdgeCount

  return (
    <div className="grid h-full min-h-[720px] grid-cols-1 xl:grid-cols-[minmax(0,1fr)_320px] gap-4">
      {/* ── Canvas ── */}
      <div className="relative min-h-[720px] overflow-hidden rounded-2xl border border-gray-200 dark:border-zinc-800">
        <div
          ref={containerRef}
          id="topology-canvas"
          className="h-full w-full"
          style={{ background: bgColor }}
        />

        {/* Floating tooltip (rendered outside Cytoscape canvas) */}
        <div
          ref={tooltipRef}
          className="pointer-events-none fixed z-50 hidden rounded-lg border border-gray-200 bg-white/95 px-3 py-2 text-xs shadow-lg backdrop-blur dark:border-zinc-700 dark:bg-zinc-900/95"
          style={{ display: 'none' }}
        />

        {/* Stats bar */}
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
          {focusAssetId && (
            <button
              type="button"
              onClick={() => setFocusAssetId(null)}
              className="ml-auto inline-flex items-center gap-1 rounded-md bg-sky-100 px-2 py-0.5 text-[11px] text-sky-700 dark:bg-sky-900/40 dark:text-sky-300"
            >
              <Eye className="h-3 w-3" /> Focused · Exit
            </button>
          )}
        </div>

        {/* Filter bar */}
        <div className="absolute left-3 top-16 flex flex-wrap gap-2">
          <select
            value={layoutMode}
            onChange={(e) => setLayoutMode(e.target.value as LayoutMode)}
            className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900"
          >
            <option value="radial">Radial</option>
            <option value="overview">Overview</option>
            <option value="hierarchy">Hierarchy</option>
            <option value="raw">Raw graph</option>
          </select>
          <select
            value={segmentFilter}
            onChange={(e) => setSegmentFilter(e.target.value)}
            className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900"
          >
            <option value="all">All segments</option>
            {(graph?.segments ?? []).map((s) => (
              <option key={s.id} value={String(s.id)}>{s.label}</option>
            ))}
          </select>
          <div className="relative">
            <Filter className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-400" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="appearance-none rounded-lg border border-gray-200 bg-white pl-7 pr-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900"
            >
              {DEVICE_FILTER_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          </div>
          <label className="inline-flex items-center gap-2 rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900">
            <input
              type="checkbox"
              checked={dimInferred}
              onChange={(e) => setDimInferred(e.target.checked)}
            />
            Dim inferred
          </label>
          {/* Search */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-400" />
            <input
              type="text"
              placeholder="Search nodes…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="rounded-lg border border-gray-200 bg-white pl-7 pr-3 py-1.5 text-xs dark:border-zinc-700 dark:bg-zinc-900 w-36"
            />
          </div>
          {/* Link-draw toggle */}
          <button
            type="button"
            onClick={() => { setLinkDrawMode((v) => !v); setLinkDrawSource(null) }}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition-colors',
              linkDrawMode
                ? 'border-sky-400 bg-sky-50 text-sky-700 dark:border-sky-600 dark:bg-sky-900/30 dark:text-sky-300'
                : 'border-gray-200 bg-white dark:border-zinc-700 dark:bg-zinc-900',
            )}
            title={linkDrawMode ? 'Cancel link drawing' : 'Draw a manual link between two nodes'}
          >
            <Link2 className="h-3.5 w-3.5" />
            {linkDrawMode
              ? (linkDrawSource ? 'Click target node…' : 'Click source node…')
              : 'Add link'}
          </button>
        </div>

        {/* Legend */}
        <div className="absolute bottom-3 left-3 flex flex-wrap gap-2 rounded-xl border border-gray-200 bg-white/95 px-3 py-2 text-[11px] shadow-sm backdrop-blur dark:border-zinc-700 dark:bg-zinc-900/95">
          <LegendSwatch color="#f59e0b" label="Gateway" />
          <LegendSwatch color="#8b5cf6" label="LLDP/CDP" />
          <LegendSwatch color="#06b6d4" label="Wireless" />
          <LegendSwatch color="#71717a" label="Inferred/ARP" dashed />
        </div>

        {/* Layout controls */}
        <div className="absolute bottom-16 right-3 flex flex-col gap-1.5">
          <MapControlButton
            title={layoutSaved ? 'Saved!' : 'Save node positions'}
            onClick={handleSaveLayout}
          >
            <span className="text-[10px] font-medium leading-none">{layoutSaved ? '✓' : '💾'}</span>
          </MapControlButton>
          <MapControlButton title="Reset saved layout" onClick={handleResetLayout}>
            <Unlink className="w-4 h-4" />
          </MapControlButton>
        </div>

        {/* Zoom controls */}
        <div className="absolute bottom-3 right-3 flex flex-col gap-1.5">
          <MapControlButton title="Zoom in" onClick={handleZoomIn}><ZoomIn className="w-4 h-4" /></MapControlButton>
          <MapControlButton title="Zoom out" onClick={handleZoomOut}><ZoomOut className="w-4 h-4" /></MapControlButton>
          <MapControlButton title="Fit" onClick={handleFit}><Maximize2 className="w-4 h-4" /></MapControlButton>
          <MapControlButton title="Refresh" onClick={handleRefresh}><RefreshCw className="w-4 h-4" /></MapControlButton>
        </div>
      </div>

      {/* ── Detail Panel ── */}
      <aside className="rounded-2xl border border-gray-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950 overflow-y-auto">
        <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">Topology Detail</h3>
        <p className="mt-1 text-xs text-zinc-500">
          Select a node or edge to inspect it. Click a node twice to focus its neighbourhood.
        </p>

        {!selectedItem ? (
          <DefaultPanel
            filteredGraph={filteredGraph}
            fullSegments={graph?.segments ?? []}
          />
        ) : selectedItem.kind === 'node' ? (
          <NodeDetailPanel
            data={selectedItem.data}
            infrastructureNodes={filteredGraph.nodes.filter(isInfrastructureNode)}
            onOpenAsset={() => router.push(`/assets/${selectedItem.data.id}`)}
            onFocus={() => setFocusAssetId(String(selectedItem.data.id))}
            onUpdateDeviceType={(type) => {
              updateAsset.mutate({ id: String(selectedItem.data.id), payload: { device_type: type } })
            }}
            onReparent={(parentId) => {
              createLink.mutate({
                source_id: parentId,
                target_id: String(selectedItem.data.id),
                relationship_type: 'neighbor_l2',
                observed: true,
                confidence: 1.0,
              })
            }}
          />
        ) : (
          <EdgeDetailPanel
            data={selectedItem.data}
            onConfirm={() => {
              const linkId = selectedItem.data.link_id as number | undefined
              if (linkId != null) {
                updateLink.mutate({ linkId, payload: { observed: true } })
              }
            }}
            onDeny={() => {
              const linkId = selectedItem.data.link_id as number | undefined
              if (linkId != null) {
                updateLink.mutate({ linkId, payload: { suppressed: true } })
              }
            }}
            isPending={updateLink.isPending}
          />
        )}
      </aside>

      {/* ── Link creation dialog ── */}
      {showLinkDialog && pendingLink && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="w-80 rounded-2xl border border-gray-200 bg-white p-5 shadow-xl dark:border-zinc-700 dark:bg-zinc-900">
            <h4 className="text-sm font-semibold text-zinc-900 dark:text-white mb-3">Create manual link</h4>
            <p className="text-xs text-zinc-500 mb-4">
              {pendingLink.source.slice(0, 8)} → {pendingLink.target.slice(0, 8)}
            </p>
            <label className="block text-xs text-zinc-500 mb-1">Relationship type</label>
            <select
              value={linkDrawRelType}
              onChange={(e) => setLinkDrawRelType(e.target.value)}
              className="w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-800 mb-4"
            >
              {RELATIONSHIP_TYPES.map((t) => (
                <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
              ))}
            </select>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => handleConfirmLink(linkDrawRelType)}
                className="flex-1 rounded-lg bg-sky-500 px-3 py-2 text-sm text-white hover:bg-sky-600"
              >
                Create
              </button>
              <button
                type="button"
                onClick={() => { setShowLinkDialog(false); setPendingLink(null) }}
                className="flex-1 rounded-lg border border-gray-200 px-3 py-2 text-sm dark:border-zinc-700"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── sub-components ───────────────────────────────────────────────────────────

function DefaultPanel({
  filteredGraph,
  fullSegments,
}: Readonly<{
  filteredGraph: { segments: Array<{ id: number; label: string; gateway_asset_id?: string | null }> }
  fullSegments: Array<{ id: number; label: string; gateway_asset_id?: string | null }>
}>) {
  return (
    <div className="mt-4 space-y-4">
      <div className="rounded-xl border border-gray-200 p-3 dark:border-zinc-800">
        <p className="text-xs font-medium text-zinc-500">Segments</p>
        <div className="mt-2 space-y-2">
          {(filteredGraph.segments.length > 0 ? filteredGraph.segments : fullSegments).map((segment) => (
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
          <strong>Radial</strong> fans each segment around its hub. <strong>Overview</strong> uses tier columns. <strong>Hierarchy</strong> renders the parent-child tree top-down. <strong>Raw graph</strong> uses force layout for debugging.
        </p>
      </div>
    </div>
  )
}

function NodeDetailPanel({
  data,
  infrastructureNodes,
  onOpenAsset,
  onFocus,
  onUpdateDeviceType,
  onReparent,
}: Readonly<{
  data: Record<string, unknown>
  infrastructureNodes: TopologyNode[]
  onOpenAsset: () => void
  onFocus: () => void
  onUpdateDeviceType: (type: string) => void
  onReparent: (parentId: string) => void
}>) {
  const [editingType, setEditingType] = useState(false)
  const [reparentOpen, setReparentOpen] = useState(false)

  return (
    <div className="mt-4 space-y-4">
      <div>
        <p className="text-base font-semibold text-zinc-900 dark:text-white">{String(data.label ?? data.ip ?? 'Asset')}</p>
        <p className="text-xs text-zinc-500">{String(data.ip ?? '')}</p>
      </div>
      <dl className="space-y-2 text-sm">
        <DetailRow label="Role" value={String(data.topology_role ?? 'unknown')} />

        {/* Inline device type editor */}
        <div className="flex items-start justify-between gap-3">
          <dt className="text-sm text-zinc-500">Device type</dt>
          <dd className="text-right">
            {editingType ? (
              <select
                autoFocus
                defaultValue={String(data.device_type ?? 'unknown')}
                onBlur={(e) => { onUpdateDeviceType(e.target.value); setEditingType(false) }}
                onChange={(e) => { onUpdateDeviceType(e.target.value); setEditingType(false) }}
                className="rounded border border-gray-200 bg-white px-2 py-0.5 text-xs dark:border-zinc-700 dark:bg-zinc-800"
              >
                {DEVICE_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
              </select>
            ) : (
              <button
                type="button"
                onClick={() => setEditingType(true)}
                className="text-sm text-zinc-900 dark:text-zinc-100 underline-offset-2 hover:underline"
                title="Click to edit"
              >
                {String(data.device_type ?? 'unknown')}
              </button>
            )}
          </dd>
        </div>

        <DetailRow label="Segment" value={String(data.segment_cidr ?? 'unassigned')} />
        <DetailRow label="Status" value={String(data.status ?? 'unknown')} />
        <DetailRow label="Confidence" value={typeof data.topology_confidence === 'number' ? `${Math.round(Number(data.topology_confidence) * 100)}%` : '—'} />
        <DetailRow label="Tier hint" value={String(data.tier_hint ?? '—')} />
        <DetailRow label="Latency" value={typeof data.avg_latency_ms === 'number' ? `${data.avg_latency_ms} ms` : '—'} />
        <DetailRow label="TTL distance" value={typeof data.ttl_distance === 'number' ? String(data.ttl_distance) : '—'} />
        <DetailRow label="Vendor" value={String(data.vendor ?? '—')} />
        <DetailRow label="OS" value={String(data.os ?? '—')} />
      </dl>

      {/* Re-parent */}
      <div>
        <button
          type="button"
          onClick={() => setReparentOpen((v) => !v)}
          className="inline-flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200"
        >
          <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', reparentOpen && 'rotate-180')} />
          Re-parent to…
        </button>
        {reparentOpen && (
          <select
            className="mt-2 w-full rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs dark:border-zinc-700 dark:bg-zinc-800"
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) {
                onReparent(e.target.value)
                setReparentOpen(false)
              }
            }}
          >
            <option value="" disabled>Select infrastructure parent…</option>
            {infrastructureNodes
              .filter((n) => n.data.id !== String(data.id))
              .map((n) => (
                <option key={n.data.id} value={n.data.id}>
                  {n.data.label || n.data.ip} ({String(n.data.topology_role ?? 'infra')})
                </option>
              ))}
          </select>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={onOpenAsset}
          className="inline-flex items-center gap-2 rounded-lg bg-sky-500 px-3 py-2 text-sm text-white hover:bg-sky-600"
        >
          <ArrowRight className="h-4 w-4" />
          Open asset
        </button>
        <button
          type="button"
          onClick={onFocus}
          className="inline-flex items-center gap-2 rounded-lg border border-gray-200 px-3 py-2 text-sm dark:border-zinc-700 hover:bg-gray-50 dark:hover:bg-zinc-800"
        >
          <Eye className="h-4 w-4" />
          Focus
        </button>
      </div>
    </div>
  )
}

function EdgeDetailPanel({
  data,
  onConfirm,
  onDeny,
  isPending,
}: Readonly<{
  data: Record<string, unknown>
  onConfirm: () => void
  onDeny: () => void
  isPending: boolean
}>) {
  const evidence = (data.evidence && typeof data.evidence === 'object' ? data.evidence : null) as Record<string, unknown> | null
  const isInferred = data.observed === false
  const hasLinkId = data.link_id != null

  return (
    <div className="mt-4 space-y-4">
      <div>
        <p className="text-base font-semibold text-zinc-900 dark:text-white capitalize">
          {String(data.relationship_type ?? data.link_type ?? 'Link').replace(/_/g, ' ')}
        </p>
        <p className="text-xs text-zinc-500">
          {String(data.source ?? '').slice(0, 8)} → {String(data.target ?? '').slice(0, 8)}
        </p>
      </div>
      <dl className="space-y-2 text-sm">
        <DetailRow label="Observed" value={data.observed === false ? 'No (inferred)' : 'Yes'} />
        <DetailRow label="Confidence" value={typeof data.confidence === 'number' ? `${Math.round(Number(data.confidence) * 100)}%` : '—'} />
        <DetailRow label="Source" value={String(data.source_kind ?? '—')} />
        <DetailRow label="SSID" value={String(data.ssid ?? '—')} />
        <DetailRow label="Local interface" value={String(data.local_interface ?? '—')} />
        <DetailRow label="Remote interface" value={String(data.remote_interface ?? '—')} />
      </dl>

      {/* Confirm / Deny — only for inferred links that have been persisted */}
      {isInferred && hasLinkId && (
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onConfirm}
            disabled={isPending}
            className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-2 text-sm text-white hover:bg-emerald-600 disabled:opacity-50"
          >
            <CheckCircle className="h-4 w-4" />
            Confirm
          </button>
          <button
            type="button"
            onClick={onDeny}
            disabled={isPending}
            className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-red-500 px-3 py-2 text-sm text-white hover:bg-red-600 disabled:opacity-50"
          >
            <XCircle className="h-4 w-4" />
            Deny
          </button>
        </div>
      )}
      {isInferred && !hasLinkId && (
        <p className="text-xs text-zinc-400">
          This edge is computed at render time and not yet persisted. Run a scan to generate a DB-backed link that can be confirmed or denied.
        </p>
      )}

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

// ─── utilities ────────────────────────────────────────────────────────────────

function buildCytoscapeStyle(labelColor: string): cytoscape.Stylesheet[] {
  return [
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
      style: { 'width': 56, 'height': 56, 'border-width': 4 },
    },
    {
      selector: 'node.highlighted',
      style: {
        'border-color': '#0ea5e9',
        'border-width': 5,
        'overlay-color': '#0ea5e9',
        'overlay-opacity': 0.15,
        'overlay-padding': 8,
      },
    },
    {
      selector: 'edge',
      style: {
        'width': 'data(edgeWidth)' as any,
        'line-color': 'data(color)',
        'target-arrow-color': 'data(color)',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'opacity': 'data(edgeOpacity)' as any,
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
  ]
}

function LegendSwatch({ color, label, dashed = false }: Readonly<{ color: string; label: string; dashed?: boolean }>) {
  return (
    <div className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-400">
      <span className={cn('inline-block w-5 border-t-2', dashed && 'border-dashed')} style={{ borderColor: color }} />
      {label}
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
