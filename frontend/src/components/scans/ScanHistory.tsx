'use client'

import { useState } from 'react'
import { StatusBadge } from '@/components/ui/Badge'
import { timeAgo, formatDate, shortId } from '@/lib/utils'
import type { ScanJob } from '@/types'
import { Clock, Server, Cpu, ChevronRight, ChevronDown } from 'lucide-react'

interface ScanHistoryProps {
  scans: ScanJob[]
  isLoading: boolean
}

export function ScanHistory({ scans, isLoading }: ScanHistoryProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  if (isLoading) {
    return (
      <div className="rounded-xl border border-gray-200 dark:border-zinc-800 overflow-hidden bg-white dark:bg-zinc-900">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50 dark:bg-zinc-800/50">
                {['ID', 'Targets', 'Profile', 'Status', 'Hosts', 'Duration', 'Triggered By', 'Started'].map((h) => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
              {[...Array(5)].map((_, i) => (
                <tr key={i}>
                  {[...Array(8)].map((_, j) => (
                    <td key={j} className="px-4 py-3">
                      <div className="h-4 bg-zinc-200 dark:bg-zinc-800 rounded animate-pulse" style={{ width: `${50 + j * 8}%` }} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  if (scans.length === 0) {
    return (
      <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-4 py-16 text-center">
        <Server className="w-10 h-10 text-zinc-300 dark:text-zinc-700 mx-auto mb-3" />
        <p className="text-zinc-400 text-sm">No scans yet. Trigger a scan above to get started.</p>
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-gray-200 dark:border-zinc-800 overflow-hidden bg-white dark:bg-zinc-900">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50 dark:bg-zinc-800/50">
              {['', 'ID', 'Targets', 'Profile', 'Status', 'Hosts', 'Duration', 'Triggered By', 'Started'].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
            {scans.map((scan) => (
              <ScanRow
                key={scan.id}
                scan={scan}
                isExpanded={!!expanded[scan.id]}
                onToggle={() => setExpanded((current) => ({ ...current, [scan.id]: !current[scan.id] }))}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ScanRow({
  scan,
  isExpanded,
  onToggle,
}: {
  scan: ScanJob
  isExpanded: boolean
  onToggle: () => void
}) {
  const summary = scan.result_summary as any
  const duration = scan.started_at && scan.finished_at
    ? Math.round((new Date(scan.finished_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
    : null

  const targets = Array.isArray(scan.targets) ? scan.targets.join(', ') : scan.targets ?? '—'
  const canExpand = scan.status === 'running'
  const details = buildScanDetails(scan)

  return (
    <>
      <tr className="hover:bg-gray-50 dark:hover:bg-zinc-800/50 transition-colors">
        <td className="px-4 py-3">
          {canExpand ? (
            <button
              type="button"
              onClick={onToggle}
              className="inline-flex items-center justify-center w-6 h-6 rounded hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-500"
              aria-label={isExpanded ? 'Collapse scan details' : 'Expand scan details'}
            >
              {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            </button>
          ) : null}
        </td>

        <td className="px-4 py-3">
          <span className="font-mono text-xs text-zinc-500 dark:text-zinc-400">{shortId(scan.id)}</span>
        </td>

        <td className="px-4 py-3">
          <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300 max-w-[180px] block truncate" title={targets}>
            {targets}
          </span>
        </td>

        <td className="px-4 py-3">
          <ProfileBadge profile={scan.scan_type} />
        </td>

        <td className="px-4 py-3">
          <div className="space-y-1">
            <ScanStatusBadge status={scan.status} />
            {scan.status === 'running' && summary?.stage && (
              <p className="text-[11px] text-zinc-500 capitalize">{summary.stage.replace('_', ' ')}</p>
            )}
            {scan.status === 'running' && summary?.message && (
              <p className="text-[11px] text-zinc-400 max-w-[220px] truncate" title={summary.message}>
                {summary.message}
              </p>
            )}
          </div>
        </td>

        <td className="px-4 py-3">
          {summary ? (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-zinc-700 dark:text-zinc-300 flex items-center gap-1">
                <Server className="w-3 h-3" /> {summary.hosts_found ?? '—'}
              </span>
              {scan.status === 'running' && summary?.hosts_investigated !== undefined && (
                <span className="text-sky-600 dark:text-sky-400">{summary.hosts_investigated} done</span>
              )}
              {summary?.new_assets > 0 && (
                <span className="text-emerald-600 dark:text-emerald-400">+{summary.new_assets} new</span>
              )}
              {summary?.changed_assets > 0 && (
                <span className="text-yellow-600 dark:text-yellow-400">~{summary.changed_assets} chg</span>
              )}
            </div>
          ) : (
            <span className="text-zinc-400 text-xs">—</span>
          )}
        </td>

        <td className="px-4 py-3">
          {duration !== null ? (
            <span className="text-xs text-zinc-500 flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {duration < 60 ? `${duration}s` : `${Math.floor(duration / 60)}m ${duration % 60}s`}
            </span>
          ) : scan.status === 'running' ? (
            <span className="text-xs text-sky-500 animate-pulse flex items-center gap-1">
              <Cpu className="w-3 h-3" /> scanning…
            </span>
          ) : (
            <span className="text-zinc-400 text-xs">—</span>
          )}
        </td>

        <td className="px-4 py-3">
          <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
            scan.triggered_by === 'schedule'
              ? 'bg-purple-500/10 text-purple-600 dark:text-purple-400'
              : 'bg-sky-500/10 text-sky-600 dark:text-sky-400'
          }`}>
            {scan.triggered_by ?? 'manual'}
          </span>
        </td>

        <td className="px-4 py-3 text-xs text-zinc-400 whitespace-nowrap">
          {scan.started_at ? timeAgo(scan.started_at) : formatDate(scan.created_at)}
        </td>
      </tr>
      {canExpand && isExpanded && (
        <tr className="bg-zinc-50/60 dark:bg-zinc-950/40">
          <td colSpan={9} className="px-4 py-3">
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3">
              <p className="text-[11px] uppercase tracking-wider text-zinc-500 mb-2">Live Scan Detail</p>
              <div className="rounded-md bg-zinc-950 text-zinc-100 p-3 font-mono text-xs leading-5 overflow-x-auto">
                {details.map((line, index) => (
                  <div key={`${scan.id}:${index}`}>{line}</div>
                ))}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function buildScanDetails(scan: ScanJob): string[] {
  const summary = (scan.result_summary ?? {}) as Record<string, unknown>
  const stage = typeof summary.stage === 'string' ? summary.stage : 'queued'
  const progress = typeof summary.progress === 'number' ? `${Math.round(summary.progress * 100)}%` : '—'
  const message = typeof summary.message === 'string' ? summary.message : 'Waiting for scanner update'
  const hostsFound = summary.hosts_found ?? '—'
  const hostsDone = summary.hosts_investigated ?? 0
  const currentHost = typeof summary.current_host === 'string' ? summary.current_host : '—'
  const newAssets = summary.new_assets ?? 0
  const changedAssets = summary.changed_assets ?? 0
  const offlineAssets = summary.offline_assets ?? 0
  const errors = Array.isArray(summary.errors) ? summary.errors.length : 0

  return [
    `[job] ${shortId(scan.id)} ${scan.status}`,
    `[targets] ${Array.isArray(scan.targets) ? scan.targets.join(', ') : scan.targets ?? '—'}`,
    `[profile] ${scan.scan_type}`,
    `[stage] ${String(stage)}`,
    `[progress] ${progress}`,
    `[message] ${message}`,
    `[hosts] found=${hostsFound} investigated=${hostsDone}`,
    `[current] ${currentHost}`,
    `[changes] new=${newAssets} changed=${changedAssets} offline=${offlineAssets}`,
    `[errors] ${errors}`,
  ]
}

function ProfileBadge({ profile }: { profile: string }) {
  const colors: Record<string, string> = {
    polite:     'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
    balanced:   'bg-sky-500/10 text-sky-600 dark:text-sky-400',
    aggressive: 'bg-red-500/10 text-red-600 dark:text-red-400',
    custom:     'bg-zinc-500/10 text-zinc-600 dark:text-zinc-400',
  }
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded font-medium capitalize ${colors[profile] ?? colors.custom}`}>
      {profile ?? 'balanced'}
    </span>
  )
}

function ScanStatusBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; dot?: string; label: string }> = {
    pending:  { cls: 'bg-zinc-500/10 text-zinc-500', dot: 'bg-zinc-400', label: 'Pending' },
    running:  { cls: 'bg-sky-500/10 text-sky-600 dark:text-sky-400', dot: 'bg-sky-500 animate-pulse', label: 'Running' },
    done:     { cls: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400', dot: 'bg-emerald-500', label: 'Done' },
    failed:   { cls: 'bg-red-500/10 text-red-600 dark:text-red-400', dot: 'bg-red-500', label: 'Failed' },
  }
  const s = map[status] ?? map.pending
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded-full font-medium ${s.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  )
}
