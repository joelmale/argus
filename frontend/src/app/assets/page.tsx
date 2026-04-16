'use client'

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { AppShell } from '@/components/layout/AppShell'
import { AssetTable } from '@/components/assets/AssetTable'
import { useAssets, useBulkDeleteAssets } from '@/hooks/useAssets'
import { useAppStore } from '@/store'
import { useQueryClient } from '@tanstack/react-query'
import { useCurrentUser } from '@/hooks/useAuth'
import { useTriggerScan } from '@/hooks/useScans'
import { assetsApi, scansApi } from '@/lib/api'
import { Search, Download, X, Boxes, FileCode2, FileJson2, Sheet, Loader2, Microscope, Trash2, ChevronDown, RefreshCw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { AlertDialog } from '@/components/ui/AlertDialog'

const STATUS_OPTIONS = ['', 'online', 'offline', 'unknown']
const TYPE_OPTIONS = ['', 'router', 'switch', 'server', 'workstation', 'nas', 'printer', 'ip_camera', 'iot_device', 'unknown']

function downloadBlob(data: Blob, filename: string) {
  const url = URL.createObjectURL(data)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

async function waitForExportJob(jobId: string) {
  for (;;) {
    const { data } = await scansApi.get(jobId)
    if (data.status === 'done') {
      return data
    }
    if (data.status === 'failed' || data.status === 'cancelled') {
      throw new Error(typeof data.result_summary?.error === 'string' ? data.result_summary.error : 'Export failed')
    }
    await new Promise((resolve) => setTimeout(resolve, 2000))
  }
}

async function exportAssetFile(
  exporter: () => Promise<{ data: { job_id?: string; status?: string } }>,
  filename: string,
  setMessage?: (message: string | null) => void,
) {
  try {
    const response = await exporter()
    const jobId = response.data.job_id
    if (!jobId) {
      throw new Error('Export job was not created')
    }
    setMessage?.(`Export queued as job ${jobId.slice(0, 8)}. Waiting for completion…`)
    await waitForExportJob(jobId)
    const file = await assetsApi.downloadExportJob(jobId)
    downloadBlob(file.data, filename)
    setMessage?.(`Downloaded ${filename}.`)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Export failed'
    setMessage?.(`Export failed: ${message}`)
  }
}

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current)
    timer.current = setTimeout(() => setDebounced(value), delayMs)
    return () => { if (timer.current) clearTimeout(timer.current) }
  }, [value, delayMs])
  return debounced
}

function AssetsPageContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()

  // Local state drives the input; debouncedSearch syncs to the URL.
  const [search, setSearch] = useState(() => searchParams.get('search') ?? '')
  // Status reads directly from the URL; no local state needed.
  const status = searchParams.get('status') ?? ''

  const [selectedAssetIds, setSelectedAssetIds] = useState<string[]>([])
  const [recentCutoff] = useState(() => Date.now() - 24 * 60 * 60 * 1000)
  const [exportOpen, setExportOpen] = useState(false)
  const [exportMessage, setExportMessage] = useState<string | null>(null)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const exportRef = useRef<HTMLDivElement>(null)
  // Keep a ref so the search-sync effect can read the current status without
  // adding it to the dependency array (which would fire on every status change,
  // duplicating the update already handled by handleStatusChange).
  const statusRef = useRef(status)

  useEffect(() => {
    statusRef.current = status
  }, [status])

  useEffect(() => {
    if (!exportOpen) return
    function handleOutsideClick(event: MouseEvent) {
      if (exportRef.current && !exportRef.current.contains(event.target as Node)) {
        setExportOpen(false)
      }
    }
    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') setExportOpen(false)
    }
    document.addEventListener('mousedown', handleOutsideClick)
    document.addEventListener('keydown', handleEscape)
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [exportOpen])
  const debouncedSearch = useDebounced(search, 300)

  async function handleExportCsv() {
    await exportAssetFile(() => assetsApi.exportCsv(), 'argus-assets.csv', setExportMessage)
  }

  async function handleExportAnsible() {
    await exportAssetFile(() => assetsApi.exportAnsible(), 'argus-inventory.ini', setExportMessage)
  }

  async function handleExportTerraform() {
    await exportAssetFile(() => assetsApi.exportTerraform(), 'argus-assets.tf.json', setExportMessage)
  }

  async function handleExportInventoryJson() {
    await exportAssetFile(() => assetsApi.exportInventoryJson(), 'argus-inventory.json', setExportMessage)
  }

  async function handleExportReportJson() {
    await exportAssetFile(() => assetsApi.exportJsonReport(), 'argus-report.json', setExportMessage)
  }

  // Sync debounced search value to the URL so browser history captures filter state.
  useEffect(() => {
    const params = new URLSearchParams()
    if (debouncedSearch) params.set('search', debouncedSearch)
    if (statusRef.current) params.set('status', statusRef.current)
    const qs = params.toString()
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false })
  }, [debouncedSearch, pathname, router])

  function handleStatusChange(newStatus: string) {
    const params = new URLSearchParams()
    if (debouncedSearch) params.set('search', debouncedSearch)
    if (newStatus) params.set('status', newStatus)
    const qs = params.toString()
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false })
  }

  const wsConnected = useAppStore((s) => s.wsConnected)
  const queryClient = useQueryClient()
  const assetQuery = useAssets({
    search: debouncedSearch || undefined,
    status: status || undefined,
    include: ['ports', 'ai'],
  })
  const { data: assets = [], isLoading, isError, dataUpdatedAt } = assetQuery

  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (wsConnected) return
    const id = setInterval(() => setNow(Date.now()), 10_000)
    return () => clearInterval(id)
  }, [wsConnected])

  const handleRefresh = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ['assets'] })
  }, [queryClient])

  const staleSeconds = dataUpdatedAt ? Math.floor((now - dataUpdatedAt) / 1000) : null
  const { data: currentUser } = useCurrentUser()
  const { mutate: triggerEnrichment, isPending: isEnrichmentPending } = useTriggerScan()
  const { mutate: bulkDeleteAssets, isPending: isBulkDeleting } = useBulkDeleteAssets()
  const canManageAssets = currentUser?.role === 'admin'

  const clearFilters = () => {
    setSearch('')
    router.replace(pathname, { scroll: false })
  }
  const hasFilters = debouncedSearch || status
  const recentDiscoveryTargets = assets
    .filter((asset) => new Date(asset.first_seen).getTime() >= recentCutoff)
    .map((asset) => asset.ip_address)
  const unresolvedTargets = assets
    .filter((asset) => {
      const ai = asset.ai_analysis
      return !asset.hostname || !asset.vendor || !ai?.vendor
    })
    .map((asset) => asset.ip_address)
  const unknownTargets = assets
    .filter((asset) => {
      const ai = asset.ai_analysis
      const deviceClass = ai?.device_class ?? asset.device_type ?? 'unknown'
      return deviceClass === 'unknown'
    })
    .map((asset) => asset.ip_address)
  const selectedCount = selectedAssetIds.length
  const visibleSelectedCount = useMemo(
    () => assets.filter((asset) => selectedAssetIds.includes(asset.id)).length,
    [assets, selectedAssetIds],
  )

  function toggleAssetSelection(assetId: string) {
    setSelectedAssetIds((current) =>
      current.includes(assetId)
        ? current.filter((id) => id !== assetId)
        : [...current, assetId],
    )
  }

  function toggleAllVisible(assetIds: string[]) {
    if (assetIds.length === 0) {
      return
    }
    setSelectedAssetIds((current) => {
      const allVisibleSelected = assetIds.every((assetId) => current.includes(assetId))
      if (allVisibleSelected) {
        return current.filter((id) => !assetIds.includes(id))
      }
      return [...new Set([...current, ...assetIds])]
    })
  }

  function handleBulkDelete() {
    if (selectedAssetIds.length === 0) return
    setDeleteDialogOpen(true)
  }

  function confirmBulkDelete() {
    setDeleteDialogOpen(false)
    bulkDeleteAssets(selectedAssetIds, {
      onSuccess: () => setSelectedAssetIds([]),
    })
  }

  return (
    <AppShell>
      <div className="w-full max-w-[120rem] mx-auto space-y-4">
        {currentUser?.role === 'admin' && (
          <div className="rounded-xl border border-gray-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Follow-up Deep Enrichment</p>
                <p className="mt-1 text-xs text-zinc-500">
                  Use the fast inventory pass for breadth, then queue deeper enrichment only where it adds value.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={isEnrichmentPending || recentDiscoveryTargets.length === 0}
                  onClick={() => triggerEnrichment({ targets: recentDiscoveryTargets.join(' '), scan_type: 'deep_enrichment' })}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-2 text-sm text-zinc-600 disabled:cursor-not-allowed disabled:text-zinc-400 dark:border-zinc-700 dark:text-zinc-300"
                >
                  {isEnrichmentPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Microscope className="w-3.5 h-3.5" />}
                  Enrich recent discoveries ({recentDiscoveryTargets.length})
                </button>
                <button
                  type="button"
                  disabled={isEnrichmentPending || unresolvedTargets.length === 0}
                  onClick={() => triggerEnrichment({ targets: unresolvedTargets.join(' '), scan_type: 'deep_enrichment' })}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-2 text-sm text-zinc-600 disabled:cursor-not-allowed disabled:text-zinc-400 dark:border-zinc-700 dark:text-zinc-300"
                >
                  {isEnrichmentPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Microscope className="w-3.5 h-3.5" />}
                  Enrich unresolved assets ({unresolvedTargets.length})
                </button>
                <button
                  type="button"
                  disabled={isEnrichmentPending || unknownTargets.length === 0}
                  onClick={() => triggerEnrichment({ targets: unknownTargets.join(' '), scan_type: 'deep_enrichment' })}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-2 text-sm text-zinc-600 disabled:cursor-not-allowed disabled:text-zinc-400 dark:border-zinc-700 dark:text-zinc-300"
                >
                  {isEnrichmentPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Microscope className="w-3.5 h-3.5" />}
                  Enrich unknown assets ({unknownTargets.length})
                </button>
              </div>
            </div>
          </div>
        )}
        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-60">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-zinc-400 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IP, hostname, vendor…"
              className={cn(
                'w-full pl-9 pr-3 py-2 rounded-lg text-sm',
                'bg-white dark:bg-zinc-900',
                'border border-gray-200 dark:border-zinc-800',
                'text-zinc-900 dark:text-white placeholder:text-zinc-400',
                'focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500',
              )}
            />
          </div>

          {/* Status filter */}
          <select
            value={status}
            onChange={(e) => handleStatusChange(e.target.value)}
            className={cn(
              'px-3 py-2 rounded-lg text-sm',
              'bg-white dark:bg-zinc-900',
              'border border-gray-200 dark:border-zinc-800',
              'text-zinc-900 dark:text-white',
              'focus:outline-none focus:ring-2 focus:ring-sky-500/50',
            )}
          >
            <option value="">All statuses</option>
            {STATUS_OPTIONS.slice(1).map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          {/* Clear */}
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white border border-gray-200 dark:border-zinc-800 hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors"
            >
              <X className="w-3.5 h-3.5" /> Clear
            </button>
          )}

          <div className="relative" ref={exportRef}>
            <button
              onClick={() => setExportOpen((o) => !o)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white border border-gray-200 dark:border-zinc-800 hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors"
              aria-haspopup="true"
              aria-expanded={exportOpen}
            >
              <Download className="w-3.5 h-3.5" />
              Export
              <ChevronDown className={cn('w-3.5 h-3.5 transition-transform', exportOpen && 'rotate-180')} />
            </button>
            {exportOpen && (
              <div className="absolute right-0 top-full z-10 mt-1 min-w-[11rem] rounded-lg border border-gray-200 bg-white py-1 shadow-md dark:border-zinc-700 dark:bg-zinc-900">
                  {([
                  { label: 'CSV', icon: Download, action: handleExportCsv },
                  { label: 'Ansible inventory', icon: Boxes, action: handleExportAnsible },
                  { label: 'Terraform data', icon: FileCode2, action: handleExportTerraform },
                  { label: 'Inventory JSON', icon: FileJson2, action: handleExportInventoryJson },
                  { label: 'Report JSON', icon: Sheet, action: handleExportReportJson },
                ] as const).map(({ label, icon: Icon, action }) => (
                  <button
                    key={label}
                    type="button"
                    onClick={() => { void action(); setExportOpen(false) }}
                    className="flex w-full items-center gap-2 px-3 py-2 text-sm text-zinc-600 hover:bg-gray-50 dark:text-zinc-300 dark:hover:bg-zinc-800"
                  >
                    <Icon className="w-3.5 h-3.5 shrink-0" />
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>

          {exportMessage && (
            <p className="text-xs text-zinc-500">
              {exportMessage}
            </p>
          )}

          <span className="flex items-center gap-2 text-sm text-zinc-500 ml-auto">
            {isLoading ? '…' : `${assets.length} assets`}
            {!wsConnected && staleSeconds !== null && staleSeconds > 30 && (
              <>
                <span className="text-xs text-zinc-400">
                  Updated {staleSeconds < 60 ? `${staleSeconds}s` : `${Math.floor(staleSeconds / 60)}m`} ago
                </span>
                <button
                  type="button"
                  onClick={handleRefresh}
                  aria-label="Refresh asset list"
                  className="p-1 rounded hover:bg-gray-100 dark:hover:bg-zinc-800 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                </button>
              </>
            )}
          </span>
        </div>

        {canManageAssets && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-gray-200 bg-white px-4 py-3 dark:border-zinc-800 dark:bg-zinc-900">
            <div className="text-sm text-zinc-500">
              {selectedCount === 0
                ? 'Select assets to delete them in bulk.'
                : `${selectedCount} selected, ${visibleSelectedCount} visible in the current filter.`}
            </div>
            <div className="flex flex-wrap gap-2">
              {selectedCount > 0 && (
                <button
                  type="button"
                  onClick={() => setSelectedAssetIds([])}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-2 text-sm text-zinc-600 dark:border-zinc-700 dark:text-zinc-300"
                >
                  <X className="w-3.5 h-3.5" />
                  Clear selection
                </button>
              )}
              <button
                type="button"
                disabled={selectedCount === 0 || isBulkDeleting}
                onClick={handleBulkDelete}
                className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 px-3 py-2 text-sm text-red-600 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-300"
              >
                {isBulkDeleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                Delete selected
              </button>
            </div>
          </div>
        )}

        <AssetTable
          assets={assets}
          isLoading={isLoading}
          isError={isError}
          canManageAssets={!!canManageAssets}
          selectedAssetIds={selectedAssetIds}
          onToggleAssetSelection={toggleAssetSelection}
          onToggleAllVisible={toggleAllVisible}
        />
      </div>

      <AlertDialog
        open={deleteDialogOpen}
        title="Delete selected assets"
        description={`Delete ${selectedAssetIds.length} selected asset${selectedAssetIds.length === 1 ? '' : 's'}? This cannot be undone.`}
        confirmLabel="Delete"
        destructive
        onConfirm={confirmBulkDelete}
        onCancel={() => setDeleteDialogOpen(false)}
      />
    </AppShell>
  )
}

export default function AssetsPage() {
  return (
    <Suspense
      fallback={(
        <AppShell>
          <div className="w-full max-w-[120rem] mx-auto text-sm text-zinc-500">
            Loading assets...
          </div>
        </AppShell>
      )}
    >
      <AssetsPageContent />
    </Suspense>
  )
}
