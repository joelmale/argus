'use client'

import { useState, type Dispatch, type ReactNode, type SetStateAction } from 'react'
import Link from 'next/link'
import { AlertTriangle, ArrowDown, ArrowUp, ArrowUpDown, Bot, Check, ChevronDown, Loader2, Microscope } from 'lucide-react'
import { useCurrentUser } from '@/hooks/useAuth'
import { useTriggerScan } from '@/hooks/useScans'
import { StatusBadge, DeviceClassBadge, ConfidenceBadge } from '@/components/ui/Badge'
import { confidenceLabel, timeAgo, cn } from '@/lib/utils'
import type { Asset } from '@/types'

type SortKey = 'ip' | 'hostname' | 'vendor' | 'type' | 'confidence' | 'ports' | 'status' | 'last_seen'
type SortDirection = 'asc' | 'desc'
type FilterKey = Exclude<SortKey, 'ip'>

interface AssetTableProps {
  readonly assets: Asset[]
  readonly isLoading: boolean
  readonly isError: boolean
}

type AssetView = {
  asset: Asset
  ai: any
  deviceClass: string
  openPorts: number
  vendorLabel: string
  hostnameLabel: string
  confidenceLabel: string
  confidenceValue: number
  statusLabel: string
  lastSeenBucket: string
}

type ColumnDef = {
  key: SortKey
  label: string
  filterKey?: FilterKey
  options?: Array<{ value: string; label: string }>
}

interface ColumnFilterMenuProps {
  readonly column: ColumnDef
  readonly filters: Record<FilterKey, string>
  readonly openFilter: FilterKey | null
  readonly setOpenFilter: Dispatch<SetStateAction<FilterKey | null>>
  readonly setFilters: Dispatch<SetStateAction<Record<FilterKey, string>>>
}

const EMPTY_VALUE = '__empty__'
const LAST_SEEN_BUCKETS = ['Last Hour', 'Today', 'This Week', 'Older']

function buildAssetView(asset: Asset): AssetView {
  const ai = (asset as any).ai_analysis
  const openPorts = (asset.ports ?? []).filter((p: any) => p.state === 'open').length
  const confidence = ai?.confidence ?? -1
  let confidenceText = '—'
  if (ai) {
    confidenceText = confidenceLabel(ai.confidence).label
  } else if (asset.device_type_source === 'manual') {
    confidenceText = 'Manual'
  } else if (asset.device_type) {
    confidenceText = 'Stored'
  }
  return {
    asset,
    ai,
    deviceClass: ai?.device_class ?? asset.device_type ?? 'unknown',
    openPorts,
    vendorLabel: ai?.vendor ?? asset.vendor ?? asset.os_name ?? '—',
    hostnameLabel: asset.hostname ?? '—',
    confidenceLabel: confidenceText,
    confidenceValue: confidence,
    statusLabel: asset.status,
    lastSeenBucket: bucketLastSeen(asset.last_seen),
  }
}

function bucketLastSeen(value: string): string {
  const ageMs = Date.now() - new Date(value).getTime()
  if (ageMs <= 60 * 60 * 1000) return 'Last Hour'
  if (ageMs <= 24 * 60 * 60 * 1000) return 'Today'
  if (ageMs <= 7 * 24 * 60 * 60 * 1000) return 'This Week'
  return 'Older'
}

function compareIp(a: string, b: string): number {
  const left = a.split('.').map(Number)
  const right = b.split('.').map(Number)
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const delta = (left[index] ?? 0) - (right[index] ?? 0)
    if (delta !== 0) return delta
  }
  return 0
}

function normalizeFilterValue(value: string | null | undefined): string {
  return value?.trim() ? value : EMPTY_VALUE
}

function filterValueMatches(current: string, selected: string) {
  return selected === '' || current === selected
}

function emptyFilters(): Record<FilterKey, string> {
  return {
    hostname: '',
    vendor: '',
    type: '',
    confidence: '',
    ports: '',
    status: '',
    last_seen: '',
  }
}

function buildEnrichmentHandler(
  assetIp: string,
  triggerEnrichment: ReturnType<typeof useTriggerScan>['mutate'],
  setQueuedEnrichmentIp: Dispatch<SetStateAction<string | null>>,
) {
  return () => {
    setQueuedEnrichmentIp(assetIp)
    triggerEnrichment(
      { targets: assetIp, scan_type: 'deep_enrichment' },
      {
        onSettled: () => setQueuedEnrichmentIp((current) => (current === assetIp ? null : current)),
      },
    )
  }
}

function sortAssets(left: AssetView, right: AssetView, sortKey: SortKey, sortDirection: SortDirection): number {
  const direction = sortDirection === 'asc' ? 1 : -1
  switch (sortKey) {
    case 'ip':
      return compareIp(left.asset.ip_address, right.asset.ip_address) * direction
    case 'hostname':
      return left.hostnameLabel.localeCompare(right.hostnameLabel) * direction
    case 'vendor':
      return left.vendorLabel.localeCompare(right.vendorLabel) * direction
    case 'type':
      return left.deviceClass.localeCompare(right.deviceClass) * direction
    case 'confidence':
      return (left.confidenceValue - right.confidenceValue) * direction
    case 'ports':
      return (left.openPorts - right.openPorts) * direction
    case 'status':
      return left.statusLabel.localeCompare(right.statusLabel) * direction
    case 'last_seen':
      return (new Date(left.asset.last_seen).getTime() - new Date(right.asset.last_seen).getTime()) * direction
  }
}

function filterMenuButtonClass(selectedValue: string): string {
  if (selectedValue) {
    return 'border-sky-500/40 bg-sky-500/10 text-sky-600 dark:text-sky-400'
  }
  return 'border-gray-200 dark:border-zinc-700 hover:text-zinc-800 dark:hover:text-zinc-200'
}

export function AssetTable({ assets, isLoading, isError }: AssetTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('ip')
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc')
  const [openFilter, setOpenFilter] = useState<FilterKey | null>(null)
  const [queuedEnrichmentIp, setQueuedEnrichmentIp] = useState<string | null>(null)
  const [filters, setFilters] = useState<Record<FilterKey, string>>(emptyFilters)
  const { data: currentUser } = useCurrentUser()
  const { mutate: triggerEnrichment, isPending: isEnrichmentPending } = useTriggerScan()

  if (isError) {
    return (
      <div className="rounded-xl border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-900/10 p-6 text-center">
        <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-2" />
        <p className="text-sm text-red-600 dark:text-red-400">Failed to load assets. Is the backend running?</p>
      </div>
    )
  }

  const views = assets.map(buildAssetView)

  const columns: ColumnDef[] = [
    { key: 'ip', label: 'IP Address' },
    {
      key: 'hostname',
      label: 'Hostname',
      filterKey: 'hostname',
      options: uniqueOptions(views.map((view) => view.asset.hostname)),
    },
    {
      key: 'vendor',
      label: 'Vendor / OS',
      filterKey: 'vendor',
      options: uniqueOptions(views.map((view) => view.ai?.vendor ?? view.asset.vendor ?? view.asset.os_name ?? null)),
    },
    {
      key: 'type',
      label: 'Type',
      filterKey: 'type',
      options: uniqueOptions(views.map((view) => view.deviceClass)),
    },
    {
      key: 'confidence',
      label: 'AI Confidence',
      filterKey: 'confidence',
      options: uniqueOptions(views.map((view) => view.confidenceLabel)),
    },
    {
      key: 'ports',
      label: 'Ports',
      filterKey: 'ports',
      options: uniqueOptions(views.map((view) => String(view.openPorts))),
    },
    {
      key: 'status',
      label: 'Status',
      filterKey: 'status',
      options: uniqueOptions(views.map((view) => view.statusLabel)),
    },
    {
      key: 'last_seen',
      label: 'Last Seen',
      filterKey: 'last_seen',
      options: LAST_SEEN_BUCKETS.map((bucket) => ({ value: bucket, label: bucket })),
    },
  ]

  const filteredViews = views.filter((view) =>
    filterValueMatches(normalizeFilterValue(view.asset.hostname), filters.hostname)
    && filterValueMatches(normalizeFilterValue(view.ai?.vendor ?? view.asset.vendor ?? view.asset.os_name), filters.vendor)
    && filterValueMatches(normalizeFilterValue(view.deviceClass), filters.type)
    && filterValueMatches(normalizeFilterValue(view.confidenceLabel), filters.confidence)
    && filterValueMatches(String(view.openPorts), filters.ports)
    && filterValueMatches(normalizeFilterValue(view.statusLabel), filters.status)
    && filterValueMatches(normalizeFilterValue(view.lastSeenBucket), filters.last_seen)
  )
  const loadingRows = Array.from({ length: 8 }, (_, index) => <SkeletonRow key={`asset-skeleton-${index}`} />)
  const sortIconByDirection = {
    asc: <ArrowUp className="w-3.5 h-3.5" />,
    desc: <ArrowDown className="w-3.5 h-3.5" />,
  } satisfies Record<SortDirection, ReactNode>

  const sortedViews = [...filteredViews].sort((left, right) => sortAssets(left, right, sortKey, sortDirection))
  let tableRows: ReactNode = sortedViews.map((view) => (
    <AssetRow
      key={view.asset.id}
      asset={view.asset}
      canEnrich={currentUser?.role === 'admin'}
      isEnriching={isEnrichmentPending && queuedEnrichmentIp === view.asset.ip_address}
      onRunEnrichment={buildEnrichmentHandler(view.asset.ip_address, triggerEnrichment, setQueuedEnrichmentIp)}
    />
  ))

  if (isLoading) {
    tableRows = loadingRows
  } else if (sortedViews.length === 0) {
    tableRows = (
      <tr>
        <td colSpan={9} className="px-4 py-16 text-center text-zinc-400">
          No assets match the current filters.
        </td>
      </tr>
    )
  }

  const hasColumnFilters = Object.values(filters).some(Boolean)

  function handleSort(column: SortKey) {
    if (sortKey === column) {
      setSortDirection((current) => (current === 'asc' ? 'desc' : 'asc'))
      return
    }
    setSortKey(column)
    setSortDirection('asc')
  }

  function clearColumnFilters() {
    setFilters(emptyFilters())
    setOpenFilter(null)
  }

  return (
    <div className="rounded-xl border border-gray-200 dark:border-zinc-800 overflow-hidden bg-white dark:bg-zinc-900">
      {hasColumnFilters && (
        <div className="flex items-center justify-between gap-3 border-b border-gray-100 dark:border-zinc-800 px-4 py-2 text-xs text-zinc-500">
          <span>Column filters active</span>
          <button
            type="button"
            onClick={clearColumnFilters}
            className="text-sky-500 hover:text-sky-600"
          >
            Clear column filters
          </button>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50 dark:bg-zinc-800/50">
              {columns.map((column) => (
                <th key={column.key} className="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => handleSort(column.key)}
                      className="inline-flex items-center gap-1 text-left hover:text-zinc-800 dark:hover:text-zinc-200"
                    >
                      {column.label}
                      {sortKey === column.key ? (
                        sortIconByDirection[sortDirection]
                      ) : (
                        <ArrowUpDown className="w-3.5 h-3.5 opacity-70" />
                      )}
                    </button>
                    {column.filterKey && column.options && (
                      <ColumnFilterMenu
                        column={column}
                        filters={filters}
                        openFilter={openFilter}
                        setOpenFilter={setOpenFilter}
                        setFilters={setFilters}
                      />
                    )}
                  </div>
                </th>
              ))}
              <th className="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
            {tableRows}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ColumnFilterMenu({ column, filters, openFilter, setOpenFilter, setFilters }: ColumnFilterMenuProps) {
  if (!column.filterKey || !column.options) {
    return null
  }

  const filterKey = column.filterKey
  const updateFilter = (value: string) => {
    setFilters((current) => ({ ...current, [filterKey]: value }))
    setOpenFilter(null)
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpenFilter((current) => (current === filterKey ? null : filterKey))}
        className={cn(
          'inline-flex items-center gap-1 rounded-md border px-1.5 py-1 normal-case',
          filterMenuButtonClass(filters[filterKey]),
        )}
      >
        <ChevronDown className="w-3.5 h-3.5" />
      </button>
      {openFilter === filterKey && (
        <FilterOptionsMenu
          options={column.options}
          selectedValue={filters[filterKey]}
          onSelect={updateFilter}
        />
      )}
    </div>
  )
}

function FilterOptionsMenu({
  options,
  selectedValue,
  onSelect,
}: Readonly<{
  options: Array<{ value: string; label: string }>
  selectedValue: string
  onSelect: (value: string) => void
}>) {
  return (
    <div className="absolute left-0 top-8 z-20 min-w-44 rounded-lg border border-gray-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 shadow-lg">
      <button
        type="button"
        onClick={() => onSelect('')}
        className="flex w-full items-center justify-between px-3 py-2 text-xs text-left hover:bg-gray-50 dark:hover:bg-zinc-800"
      >
        <span>All</span>
        {!selectedValue && <Check className="w-3.5 h-3.5 text-sky-500" />}
      </button>
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          onClick={() => onSelect(option.value)}
          className="flex w-full items-center justify-between px-3 py-2 text-xs text-left hover:bg-gray-50 dark:hover:bg-zinc-800"
        >
          <span>{option.label}</span>
          {selectedValue === option.value && <Check className="w-3.5 h-3.5 text-sky-500" />}
        </button>
      ))}
    </div>
  )
}

function uniqueOptions(values: Array<string | null | undefined>) {
  return [...new Set(values.map(normalizeFilterValue))].sort((left, right) => left.localeCompare(right)).map((value) => ({
    value,
    label: value === EMPTY_VALUE ? 'Blank' : value,
  }))
}

function AssetRow({
  asset,
  canEnrich,
  isEnriching,
  onRunEnrichment,
}: Readonly<{
  asset: Asset
  canEnrich: boolean
  isEnriching: boolean
  onRunEnrichment: () => void
}>) {
  const ai = (asset as any).ai_analysis
  const deviceClass = ai?.device_class ?? asset.device_type ?? 'unknown'
  const openPorts = (asset.ports ?? []).filter((p: any) => p.state === 'open').length
  const hasSecurityFindings = (ai?.security_findings?.length ?? 0) > 0
  const vendorText = ai?.vendor ?? asset.vendor
  const osText = ai?.os_guess ?? asset.os_name
  const deviceTypeSummary = asset.device_type ? `${asset.device_type_source} classification` : '—'

  return (
    <tr className="hover:bg-gray-50 dark:hover:bg-zinc-800/50 transition-colors group">
      <td className="px-4 py-3">
        <Link href={`/assets/${asset.id}`} className="font-mono text-sky-600 dark:text-sky-400 hover:underline tabular">
          {asset.ip_address}
        </Link>
      </td>
      <td className="px-4 py-3">
        <span className="text-zinc-700 dark:text-zinc-300 truncate max-w-32 block">
          {asset.hostname || <span className="text-zinc-400">—</span>}
        </span>
        {ai?.model && (
          <span className="text-xs text-zinc-400">{ai.model}</span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="text-zinc-700 dark:text-zinc-300 block truncate max-w-36">
          {vendorText || <span className="text-zinc-400">—</span>}
        </span>
        {osText && (
          <span className="text-xs text-zinc-400 truncate block max-w-36">
            {osText}
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        <DeviceClassBadge deviceClass={deviceClass} />
      </td>
      <td className="px-4 py-3">
        {ai ? (
          <div className="flex items-center gap-1.5">
            <Bot className="w-3.5 h-3.5 text-sky-500 flex-shrink-0" />
            <ConfidenceBadge confidence={ai.confidence} />
            {hasSecurityFindings && (
              <span title="Security findings">
                <AlertTriangle className="w-3.5 h-3.5 text-yellow-500" />
              </span>
            )}
          </div>
        ) : (
          <span className="text-xs text-zinc-400">{deviceTypeSummary}</span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="text-zinc-700 dark:text-zinc-300 tabular">{openPorts}</span>
      </td>
      <td className="px-4 py-3">
        <StatusBadge status={asset.status} />
      </td>
      <td className="px-4 py-3 text-xs text-zinc-400 whitespace-nowrap">
        {timeAgo(asset.last_seen)}
      </td>
      <td className="px-4 py-3">
        {canEnrich ? (
          <button
            type="button"
            onClick={onRunEnrichment}
            disabled={isEnriching}
            className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-2.5 py-1.5 text-[11px] text-zinc-600 hover:text-zinc-900 dark:border-zinc-700 dark:text-zinc-300 dark:hover:text-zinc-100"
          >
            {isEnriching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Microscope className="w-3.5 h-3.5" />}
            {isEnriching ? 'Queueing…' : 'Enrich'}
          </button>
        ) : (
          <span className="text-xs text-zinc-400">—</span>
        )}
      </td>
    </tr>
  )
}

function SkeletonRow() {
  const widths = Array.from({ length: 9 }, (_, index) => ({
    key: `asset-skeleton-cell-${index}`,
    width: `${60 + index * 10}%`,
  }))
  return (
    <tr>
      {widths.map((cell) => (
        <td key={cell.key} className="px-4 py-3">
          <div className="h-4 bg-zinc-200 dark:bg-zinc-800 rounded animate-pulse" style={{ width: cell.width }} />
        </td>
      ))}
    </tr>
  )
}
