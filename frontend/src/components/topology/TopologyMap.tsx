'use client'

import { useEffect, useRef, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
// @ts-ignore — fcose has no bundled types for register()
import fcose from 'cytoscape-fcose'
import { useTopologyGraph } from '@/hooks/useAssets'
import { useRouter } from 'next/navigation'
import { cn } from '@/lib/utils'
import { ZoomIn, ZoomOut, Maximize2, RefreshCw, Filter } from 'lucide-react'

// Register fcose layout once
if (globalThis.window !== undefined) {
  cytoscape.use(fcose)
}

// Device type → colour map (matches Badge.tsx palette)
const DEVICE_COLORS: Record<string, string> = {
  router:       '#f59e0b', // amber
  switch:       '#8b5cf6', // violet
  access_point: '#06b6d4', // cyan
  firewall:     '#ef4444', // red
  server:       '#3b82f6', // blue
  workstation:  '#6366f1', // indigo
  nas:          '#0ea5e9', // sky
  printer:      '#84cc16', // lime
  ip_camera:    '#ec4899', // pink
  smart_tv:     '#f97316', // orange
  iot_device:   '#10b981', // emerald
  voip:         '#14b8a6', // teal
  unknown:      '#71717a', // zinc
}

const STATUS_BORDER: Record<string, string> = {
  online:  '#10b981',
  offline: '#ef4444',
  unknown: '#71717a',
}

function deviceColor(deviceType: string | null): string {
  return DEVICE_COLORS[deviceType ?? 'unknown'] ?? DEVICE_COLORS.unknown
}

function edgeLineStyle(observed: boolean | undefined): 'solid' | 'dashed' {
  return observed === false ? 'dashed' : 'solid'
}

const DEVICE_FILTER_OPTIONS = [
  { value: 'all', label: 'All types' },
  { value: 'router', label: 'Routers' },
  { value: 'switch', label: 'Switches' },
  { value: 'server', label: 'Servers' },
  { value: 'workstation', label: 'Workstations' },
  { value: 'iot_device', label: 'IoT' },
  { value: 'unknown', label: 'Unknown' },
]

export function TopologyMap() {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef        = useRef<cytoscape.Core | null>(null)
  const router       = useRouter()

  const { data: graph, isLoading, isError, refetch } = useTopologyGraph()

  const [darkMode, setDarkMode] = useState(false)
  const [filter, setFilter]     = useState('all')
  const [tooltip, setTooltip]   = useState<{
    label: string; ip: string; vendor: string | null; os: string | null; status: string
  } | null>(null)

  // Detect dark mode from document class
  useEffect(() => {
    const observer = new MutationObserver(() => {
      setDarkMode(document.documentElement.classList.contains('dark'))
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    setDarkMode(document.documentElement.classList.contains('dark'))
    return () => observer.disconnect()
  }, [])

  const bgColor    = darkMode ? '#18181b' : '#fafafa'
  const edgeColor  = darkMode ? '#3f3f46' : '#d4d4d8'
  const labelColor = darkMode ? '#e4e4e7' : '#27272a'

  const buildElements = useCallback(() => {
    if (!graph) return []

    const nodes = graph.nodes
      .filter((n) => filter === 'all' || n.data.device_type === filter)
      .map((n) => ({
        data: {
          id:          n.data.id,
          label:       n.data.label || n.data.ip,
          ip:          n.data.ip,
          vendor:      n.data.vendor,
          os:          n.data.os,
          status:      n.data.status,
          device_type: n.data.device_type,
          color:       deviceColor(n.data.device_type),
          border:      STATUS_BORDER[n.data.status] ?? STATUS_BORDER.unknown,
        },
      }))

    const visibleIds = new Set(nodes.map((n) => n.data.id))
    const edges = graph.edges
      .filter((e) => visibleIds.has(e.data.source) && visibleIds.has(e.data.target))
      .map((e) => ({
        data: {
          id:         e.data.id,
          source:     e.data.source,
          target:     e.data.target,
          link_type:  e.data.link_type,
          confidence: e.data.confidence ?? 0.5,
          lineStyle:  edgeLineStyle(e.data.observed),
        },
      }))

    return [...nodes, ...edges]
  }, [graph, filter])

  // Initialise / re-initialise Cytoscape when graph or dark mode changes
  useEffect(() => {
    if (!containerRef.current || !graph) return

    // Destroy previous instance
    if (cyRef.current) {
      cyRef.current.destroy()
      cyRef.current = null
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements:  buildElements(),
      style: [
        {
          selector: 'node',
          style: {
            'background-color':    'data(color)',
            'border-color':        'data(border)',
            'border-width':        3,
            'label':               'data(label)',
            'color':               labelColor,
            'font-size':           11,
            'text-valign':         'bottom',
            'text-margin-y':       4,
            'text-max-width':      '90px',
            'text-overflow-wrap':  'anywhere',
            'width':               38,
            'height':              38,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 4,
            'border-color': '#0ea5e9',
          },
        },
        {
          selector: 'edge',
          style: {
            'width':            'mapData(confidence, 0, 1, 1.5, 3.5)' as any,
            'line-color':       edgeColor,
            'curve-style':      'bezier',
            'opacity':          'mapData(confidence, 0, 1, 0.35, 0.9)' as any,
            'line-style':       'data(lineStyle)' as any,
          },
        },
        {
          selector: 'edge:selected',
          style: {
            'line-color': '#0ea5e9',
            'width':      3,
            'opacity':    1,
          },
        },
      ],
      layout: {
        name:              'fcose',
        quality:           'default',
        randomize:         true,
        animate:           true,
        animationDuration: 600,
        fit:               true,
        padding:           40,
        nodeSeparation:    100,
        idealEdgeLength:   120,
      } as any,
      wheelSensitivity: 0.3,
    })

    // Node click → navigate to asset detail
    cy.on('tap', 'node', (evt) => {
      const id = evt.target.data('id')
      router.push(`/assets/${id}`)
    })

    // Node hover → tooltip
    cy.on('mouseover', 'node', (evt) => {
      setTooltip({
        label:  evt.target.data('label'),
        ip:     evt.target.data('ip'),
        vendor: evt.target.data('vendor'),
        os:     evt.target.data('os'),
        status: evt.target.data('status'),
      })
    })
    cy.on('mouseout', 'node', () => setTooltip(null))

    cyRef.current = cy

    return () => {
      cy.destroy()
      cyRef.current = null
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, darkMode, filter, labelColor, edgeColor])

  // Controls
  function handleZoomIn()  { cyRef.current?.zoom(cyRef.current.zoom() * 1.2) }
  function handleZoomOut() { cyRef.current?.zoom(cyRef.current.zoom() * 0.8) }
  function handleFit()     { cyRef.current?.fit(undefined, 40) }
  function handleRefresh() { refetch() }

  // ── Render ────────────────────────────────────────────────────────────────
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

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 text-zinc-400">
        <p className="text-sm">No topology data yet.</p>
        <p className="text-xs">Run a scan to build the network map.</p>
      </div>
    )
  }

  return (
    <div className="relative w-full h-full">
      {/* Canvas */}
      <div
        ref={containerRef}
        id="topology-canvas"
        className="w-full h-full rounded-xl"
        style={{ background: bgColor }}
      />

      {/* Controls overlay */}
      <div className="absolute top-3 right-3 flex flex-col gap-1.5">
        {[
          { Icon: ZoomIn,    fn: handleZoomIn,  title: 'Zoom in' },
          { Icon: ZoomOut,   fn: handleZoomOut, title: 'Zoom out' },
          { Icon: Maximize2, fn: handleFit,     title: 'Fit' },
          { Icon: RefreshCw, fn: handleRefresh, title: 'Refresh' },
        ].map(({ Icon, fn, title }) => (
          <button
            key={title}
            onClick={fn}
            title={title}
            className={cn(
              'w-8 h-8 flex items-center justify-center rounded-lg text-zinc-600 dark:text-zinc-300',
              'bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-700',
              'hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors shadow-sm',
            )}
          >
            <Icon className="w-4 h-4" />
          </button>
        ))}
      </div>

      {/* Filter */}
      <div className="absolute top-3 left-3">
        <div className="relative">
          <Filter className="absolute left-2.5 top-2 w-3.5 h-3.5 text-zinc-400 pointer-events-none" />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className={cn(
              'pl-7 pr-3 py-1.5 text-xs rounded-lg appearance-none',
              'bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-700',
              'text-zinc-700 dark:text-zinc-300 shadow-sm',
              'focus:outline-none focus:ring-2 focus:ring-sky-500/50',
            )}
          >
            {DEVICE_FILTER_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Legend */}
      <div className="absolute bottom-3 left-3 bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-700 rounded-lg p-2.5 shadow-sm">
        <p className="text-xs font-medium text-zinc-500 mb-1.5">Status</p>
        <div className="space-y-1">
          {[
            { color: '#10b981', label: 'Online' },
            { color: '#ef4444', label: 'Offline' },
            { color: '#71717a', label: 'Unknown' },
          ].map(({ color, label }) => (
            <div key={label} className="flex items-center gap-1.5 text-xs text-zinc-600 dark:text-zinc-400">
              <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
              {label}
            </div>
          ))}
        </div>
      </div>

      {/* Hover tooltip */}
      {tooltip && (
        <div className="absolute top-3 left-1/2 -translate-x-1/2 pointer-events-none z-10
          bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-700
          rounded-lg px-3 py-2 shadow-lg text-xs space-y-0.5 min-w-[160px]">
          <p className="font-semibold text-zinc-900 dark:text-white truncate">{tooltip.label}</p>
          <p className="font-mono text-zinc-500">{tooltip.ip}</p>
          {tooltip.vendor && <p className="text-zinc-500">{tooltip.vendor}</p>}
          {tooltip.os     && <p className="text-zinc-400 italic">{tooltip.os}</p>}
          <p className={cn('font-medium capitalize', tooltip.status === 'online' ? 'text-emerald-500' : 'text-red-500')}>
            {tooltip.status}
          </p>
        </div>
      )}

      {/* Node count */}
      <div className="absolute bottom-3 right-3 text-xs text-zinc-400">
        {graph.nodes.filter(n => filter === 'all' || n.data.device_type === filter).length} nodes · {graph.edges.length} edges
      </div>
    </div>
  )
}
