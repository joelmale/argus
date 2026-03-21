'use client'

import { useState } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { AssetTable } from '@/components/assets/AssetTable'
import { useAssets } from '@/hooks/useAssets'
import { useCurrentUser } from '@/hooks/useAuth'
import { useTriggerScan } from '@/hooks/useScans'
import { assetsApi } from '@/lib/api'
import { Search, Download, X, Boxes, FileCode2, FileJson2, Sheet, Loader2, Microscope } from 'lucide-react'
import { cn } from '@/lib/utils'

const STATUS_OPTIONS = ['', 'online', 'offline', 'unknown']
const TYPE_OPTIONS = ['', 'router', 'switch', 'server', 'workstation', 'nas', 'printer', 'ip_camera', 'iot_device', 'unknown']

export default function AssetsPage() {
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')

  const { data: assets = [], isLoading, isError } = useAssets({
    search: search || undefined,
    status: status || undefined,
  })
  const { data: currentUser } = useCurrentUser()
  const { mutate: triggerEnrichment, isPending: isEnrichmentPending } = useTriggerScan()

  const clearFilters = () => { setSearch(''); setStatus('') }
  const hasFilters = search || status
  const recentDiscoveryTargets = assets
    .filter((asset) => Date.now() - new Date(asset.first_seen).getTime() <= 24 * 60 * 60 * 1000)
    .map((asset) => asset.ip_address)
  const unresolvedTargets = assets
    .filter((asset) => {
      const ai = (asset as any).ai_analysis
      return !asset.hostname || !asset.vendor || !ai?.vendor
    })
    .map((asset) => asset.ip_address)
  const unknownTargets = assets
    .filter((asset) => {
      const ai = (asset as any).ai_analysis
      const deviceClass = ai?.device_class ?? asset.device_type ?? 'unknown'
      return deviceClass === 'unknown'
    })
    .map((asset) => asset.ip_address)

  async function handleExportCsv() {
    const response = await assetsApi.exportCsv()
    downloadBlob(response.data, 'argus-assets.csv')
  }

  async function handleExportAnsible() {
    const response = await assetsApi.exportAnsible()
    downloadBlob(response.data, 'argus-inventory.ini')
  }

  async function handleExportTerraform() {
    const response = await assetsApi.exportTerraform()
    downloadBlob(response.data, 'argus-assets.tf.json')
  }

  async function handleExportInventoryJson() {
    const response = await assetsApi.exportInventoryJson()
    downloadBlob(response.data, 'argus-inventory.json')
  }

  async function handleExportReportJson() {
    const response = await assetsApi.exportJsonReport()
    downloadBlob(response.data, 'argus-report.json')
  }

  function downloadBlob(data: Blob, filename: string) {
    const url = URL.createObjectURL(data)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <AppShell>
      <div className="space-y-4 max-w-7xl mx-auto">
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
            onChange={(e) => setStatus(e.target.value)}
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

          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white border border-gray-200 dark:border-zinc-800 hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> Export CSV
          </button>

          <button
            onClick={handleExportAnsible}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white border border-gray-200 dark:border-zinc-800 hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors"
          >
            <Boxes className="w-3.5 h-3.5" /> Ansible inventory
          </button>

          <button
            onClick={handleExportTerraform}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white border border-gray-200 dark:border-zinc-800 hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors"
          >
            <FileCode2 className="w-3.5 h-3.5" /> Terraform data
          </button>

          <button
            onClick={handleExportInventoryJson}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white border border-gray-200 dark:border-zinc-800 hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors"
          >
            <FileJson2 className="w-3.5 h-3.5" /> Inventory JSON
          </button>

          <button
            onClick={handleExportReportJson}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white border border-gray-200 dark:border-zinc-800 hover:bg-gray-50 dark:hover:bg-zinc-800 transition-colors"
          >
            <Sheet className="w-3.5 h-3.5" /> Report JSON
          </button>

          <span className="text-sm text-zinc-500 ml-auto">
            {isLoading ? '…' : `${assets.length} assets`}
          </span>
        </div>

        <AssetTable assets={assets} isLoading={isLoading} isError={isError} />
      </div>
    </AppShell>
  )
}
