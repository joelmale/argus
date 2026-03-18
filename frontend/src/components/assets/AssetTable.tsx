'use client'

import Link from 'next/link'
import { StatusBadge, DeviceClassBadge, ConfidenceBadge } from '@/components/ui/Badge'
import { timeAgo } from '@/lib/utils'
import { AlertTriangle, Bot } from 'lucide-react'
import type { Asset } from '@/types'

interface AssetTableProps {
  assets: Asset[]
  isLoading: boolean
  isError: boolean
}

export function AssetTable({ assets, isLoading, isError }: AssetTableProps) {
  if (isError) {
    return (
      <div className="rounded-xl border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-900/10 p-6 text-center">
        <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-2" />
        <p className="text-sm text-red-600 dark:text-red-400">Failed to load assets. Is the backend running?</p>
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-gray-200 dark:border-zinc-800 overflow-hidden bg-white dark:bg-zinc-900">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50 dark:bg-zinc-800/50">
              {['IP Address', 'Hostname', 'Vendor / OS', 'Type', 'AI Confidence', 'Ports', 'Status', 'Last Seen'].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
            {isLoading
              ? [...Array(8)].map((_, i) => <SkeletonRow key={i} />)
              : assets.length === 0
              ? (
                <tr>
                  <td colSpan={8} className="px-4 py-16 text-center text-zinc-400">
                    No assets found. Run a scan to discover devices on your network.
                  </td>
                </tr>
              )
              : assets.map((asset) => <AssetRow key={asset.id} asset={asset} />)
            }
          </tbody>
        </table>
      </div>
    </div>
  )
}

function AssetRow({ asset }: { asset: Asset }) {
  const ai = (asset as any).ai_analysis
  const deviceClass = ai?.device_class ?? asset.device_type ?? 'unknown'
  const openPorts = (asset.ports ?? []).filter((p: any) => p.state === 'open').length
  const hasSecurityFindings = (ai?.security_findings?.length ?? 0) > 0

  return (
    <tr className="hover:bg-gray-50 dark:hover:bg-zinc-800/50 transition-colors group">
      {/* IP */}
      <td className="px-4 py-3">
        <Link href={`/assets/${asset.id}`}
          className="font-mono text-sky-600 dark:text-sky-400 hover:underline tabular">
          {asset.ip_address}
        </Link>
      </td>

      {/* Hostname */}
      <td className="px-4 py-3">
        <span className="text-zinc-700 dark:text-zinc-300 truncate max-w-32 block">
          {asset.hostname || <span className="text-zinc-400">—</span>}
        </span>
        {ai?.model && (
          <span className="text-xs text-zinc-400">{ai.model}</span>
        )}
      </td>

      {/* Vendor / OS */}
      <td className="px-4 py-3">
        <span className="text-zinc-700 dark:text-zinc-300 block truncate max-w-36">
          {ai?.vendor ?? asset.vendor ?? <span className="text-zinc-400">—</span>}
        </span>
        {(ai?.os_guess ?? asset.os_name) && (
          <span className="text-xs text-zinc-400 truncate block max-w-36">
            {ai?.os_guess ?? asset.os_name}
          </span>
        )}
      </td>

      {/* Device class */}
      <td className="px-4 py-3">
        <DeviceClassBadge deviceClass={deviceClass} />
      </td>

      {/* AI confidence */}
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
          <span className="text-xs text-zinc-400">{asset.device_type ? 'stored classification' : '—'}</span>
        )}
      </td>

      {/* Open ports count */}
      <td className="px-4 py-3">
        <span className="text-zinc-700 dark:text-zinc-300 tabular">{openPorts}</span>
      </td>

      {/* Status */}
      <td className="px-4 py-3">
        <StatusBadge status={asset.status} />
      </td>

      {/* Last seen */}
      <td className="px-4 py-3 text-xs text-zinc-400 whitespace-nowrap">
        {timeAgo(asset.last_seen)}
      </td>
    </tr>
  )
}

function SkeletonRow() {
  return (
    <tr>
      {[...Array(8)].map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-zinc-200 dark:bg-zinc-800 rounded animate-pulse" style={{ width: `${60 + i * 10}%` }} />
        </td>
      ))}
    </tr>
  )
}
