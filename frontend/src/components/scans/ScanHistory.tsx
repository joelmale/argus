'use client'

import { useState } from 'react'
import { timeAgo, formatDate, shortId } from '@/lib/utils'
import type { ScanJob } from '@/types'
import { useCurrentUser } from '@/hooks/useAuth'
import { useControlScan, useQueueScan } from '@/hooks/useScans'
import { Clock, Server, Cpu, ChevronRight, ChevronDown } from 'lucide-react'

interface ScanHistoryProps {
  readonly scans: ScanJob[]
  readonly isLoading: boolean
}

type ControlPayload = {
  id: string
  action: 'cancel' | 'pause' | 'resume'
  mode?: 'discard' | 'preserve_discovery'
  resume_in_minutes?: number
}

type QueuePayload = {
  id: string
  action: 'move_up' | 'move_down' | 'move_to_front' | 'start_now'
}

type ScanRowProps = Readonly<{
  scan: ScanJob
  isViewer: boolean
  isControlling: boolean
  onControl: (payload: ControlPayload) => void
  onQueueAction: (payload: QueuePayload) => void
  isExpanded: boolean
  onToggle: () => void
}>

function buildScanTableHeaders(includeExpander: boolean) {
  const labels = includeExpander
    ? ['', 'ID', 'Targets', 'Profile', 'Status', 'Hosts', 'Duration', 'Triggered By', 'Started']
    : ['ID', 'Targets', 'Profile', 'Status', 'Hosts', 'Duration', 'Triggered By', 'Started']
  return labels.map((label) => ({ key: label || 'expander', label }))
}

function buildSkeletonRowWidths(columnCount: number) {
  return Array.from({ length: columnCount }, (_, index) => ({
    key: `skeleton-width-${index}`,
    width: `${50 + index * 8}%`,
  }))
}

export function ScanHistory({ scans, isLoading }: ScanHistoryProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const { data: currentUser } = useCurrentUser()
  const { mutate: controlScan, isPending: isControlling } = useControlScan()
  const { mutate: queueScan, isPending: isQueueing } = useQueueScan()
  const isViewer = currentUser?.role === 'viewer'

  if (isLoading) {
    return (
      <div className="rounded-xl border border-gray-200 dark:border-zinc-800 overflow-hidden bg-white dark:bg-zinc-900">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50 dark:bg-zinc-800/50">
                {buildScanTableHeaders(false).map((header) => (
                  <th key={header.key} className="text-left px-4 py-3 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                    {header.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
              {Array.from({ length: 5 }, (_, rowIndex) => (
                <tr key={`scan-skeleton-row-${rowIndex}`}>
                  {buildSkeletonRowWidths(8).map((cell) => (
                    <td key={cell.key} className="px-4 py-3">
                      <div className="h-4 bg-zinc-200 dark:bg-zinc-800 rounded animate-pulse" style={{ width: cell.width }} />
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
              {buildScanTableHeaders(true).map((header) => (
                <th key={header.key} className="text-left px-4 py-3 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider whitespace-nowrap">
                  {header.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
            {scans.map((scan) => (
              <ScanRow
                key={scan.id}
                scan={scan}
                isViewer={!!isViewer}
                isControlling={isControlling || isQueueing}
                onControl={(payload) => controlScan(payload)}
                onQueueAction={(payload) => queueScan(payload)}
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
  isViewer,
  isControlling,
  onControl,
  onQueueAction,
  isExpanded,
  onToggle,
}: ScanRowProps) {
  const summary = scan.result_summary as Record<string, unknown> | undefined ?? {}
  const duration = getScanDurationSeconds(scan)
  const targets = Array.isArray(scan.targets) ? scan.targets.join(', ') : scan.targets ?? '—'
  const canExpand = canExpandScan(scan.status)
  const details = buildScanDetails(scan)
  const pauseOptions = [15, 30, 60, 240, 720]
  const hostsFound = readSummaryValue(summary, 'hosts_found', '—')
  const hostsInvestigated = typeof summary.hosts_investigated === 'number' ? summary.hosts_investigated : undefined
  const newAssets = typeof summary.new_assets === 'number' ? summary.new_assets : 0
  const changedAssets = typeof summary.changed_assets === 'number' ? summary.changed_assets : 0
  const stageText = formatSummaryStage(summary)
  const messageText = typeof summary.message === 'string' ? summary.message : null
  const triggeredByClass = scan.triggered_by === 'schedule'
    ? 'bg-purple-500/10 text-purple-600 dark:text-purple-400'
    : 'bg-sky-500/10 text-sky-600 dark:text-sky-400'
  const statusActions = !isViewer ? renderScanActions(scan, pauseOptions, isControlling, onControl, onQueueAction) : null

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
            {stageText && (
              <p className="text-[11px] text-zinc-500 capitalize">{stageText}</p>
            )}
            {messageText && (
              <p className="text-[11px] text-zinc-400 max-w-[220px] truncate" title={messageText}>
                {messageText}
              </p>
            )}
            {scan.status === 'paused' && scan.resume_after && (
              <p className="text-[11px] text-amber-500">resumes {timeAgo(scan.resume_after)}</p>
            )}
            {scan.status === 'pending' && typeof scan.queue_position === 'number' && (
              <p className="text-[11px] text-zinc-500">queue #{scan.queue_position}</p>
            )}
          </div>
        </td>

        <td className="px-4 py-3">
          {scan.result_summary ? (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-zinc-700 dark:text-zinc-300 flex items-center gap-1">
                <Server className="w-3 h-3" /> {hostsFound}
              </span>
              {scan.status === 'running' && hostsInvestigated !== undefined && (
                <span className="text-sky-600 dark:text-sky-400">{hostsInvestigated} done</span>
              )}
              {newAssets > 0 && (
                <span className="text-emerald-600 dark:text-emerald-400">+{newAssets} new</span>
              )}
              {changedAssets > 0 && (
                <span className="text-yellow-600 dark:text-yellow-400">~{changedAssets} chg</span>
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
          <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${triggeredByClass}`}>
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
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3 space-y-3">
              {!isViewer && (
                <div className="flex flex-wrap gap-2">{statusActions}</div>
              )}
              <p className="text-[11px] uppercase tracking-wider text-zinc-500 mb-2">Live Scan Detail</p>
              <div className="rounded-md bg-zinc-950 text-zinc-100 p-3 font-mono text-xs leading-5 overflow-x-auto">
                {details.map((line) => (
                  <div key={`${scan.id}:${line}`}>{line}</div>
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
  const summary = scan.result_summary as Record<string, unknown> | undefined ?? {}
  const stage = typeof summary.stage === 'string' ? summary.stage : 'queued'
  const progress = typeof summary.progress === 'number' ? `${Math.round(summary.progress * 100)}%` : '—'
  const message = typeof summary.message === 'string' ? summary.message : 'Waiting for scanner update'
  const hostsFound = stringifySummaryValue(summary.hosts_found, '—')
  const hostsDone = stringifySummaryValue(summary.hosts_investigated, '0')
  const currentHost = typeof summary.current_host === 'string' ? summary.current_host : '—'
  const newAssets = stringifySummaryValue(summary.new_assets, '0')
  const changedAssets = stringifySummaryValue(summary.changed_assets, '0')
  const offlineAssets = stringifySummaryValue(summary.offline_assets, '0')
  const errors = Array.isArray(summary.errors) ? summary.errors.length : 0
  const resumeAfter = typeof scan.resume_after === 'string' ? scan.resume_after : '—'
  const preservedHosts = stringifySummaryValue(summary.preserved_hosts, '0')
  const queuePosition = typeof scan.queue_position === 'number' ? String(scan.queue_position) : '—'

  return [
    `[job] ${shortId(scan.id)} ${scan.status}`,
    `[queue] ${queuePosition}`,
    `[targets] ${Array.isArray(scan.targets) ? scan.targets.join(', ') : scan.targets ?? '—'}`,
    `[profile] ${scan.scan_type}`,
    `[stage] ${String(stage)}`,
    `[progress] ${progress}`,
    `[message] ${message}`,
    `[hosts] found=${hostsFound} investigated=${hostsDone}`,
    `[current] ${currentHost}`,
    `[resume_after] ${resumeAfter}`,
    `[preserved_hosts] ${preservedHosts}`,
    `[changes] new=${newAssets} changed=${changedAssets} offline=${offlineAssets}`,
    `[errors] ${errors}`,
  ]
}

function stringifySummaryValue(value: unknown, fallback: string): string {
  if (typeof value === 'number' || typeof value === 'string') {
    return String(value)
  }
  return fallback
}

function buildActionButton(
  key: string,
  label: string,
  className: string,
  disabled: boolean,
  onClick: () => void,
) {
  return (
    <button
      key={key}
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={className}
    >
      {label}
    </button>
  )
}

function renderScanActions(
  scan: ScanJob,
  pauseOptions: number[],
  isControlling: boolean,
  onControl: (payload: ControlPayload) => void,
  onQueueAction: (payload: QueuePayload) => void,
) {
  const actions: React.JSX.Element[] = []
  if (scan.status === 'running') {
    actions.push(
      buildActionButton(
        `${scan.id}:cancel-discard`,
        'Stop scan',
        'px-3 py-1.5 rounded-lg text-xs border border-red-200 text-red-600 dark:border-red-900 dark:text-red-300 disabled:opacity-50',
        isControlling,
        () => onControl({ id: scan.id, action: 'cancel', mode: 'discard' }),
      ),
      buildActionButton(
        `${scan.id}:cancel-preserve`,
        'Stop and keep discovered hosts',
        'px-3 py-1.5 rounded-lg text-xs border border-amber-200 text-amber-700 dark:border-amber-900 dark:text-amber-300 disabled:opacity-50',
        isControlling,
        () => onControl({ id: scan.id, action: 'cancel', mode: 'preserve_discovery' }),
      ),
      ...pauseOptions.map((minutes) => buildActionButton(
        `${scan.id}:pause:${minutes}`,
        `Pause ${formatPauseLabel(minutes)}`,
        'px-3 py-1.5 rounded-lg text-xs border border-sky-200 text-sky-700 dark:border-sky-900 dark:text-sky-300 disabled:opacity-50',
        isControlling,
        () => onControl({ id: scan.id, action: 'pause', resume_in_minutes: minutes }),
      )),
    )
  }
  if (scan.status === 'pending') {
    const queueActions: Array<{ action: QueuePayload['action']; label: string; className: string }> = [
      { action: 'move_up', label: 'Move up', className: 'px-3 py-1.5 rounded-lg text-xs border border-zinc-200 text-zinc-700 dark:border-zinc-700 dark:text-zinc-300 disabled:opacity-50' },
      { action: 'move_down', label: 'Move down', className: 'px-3 py-1.5 rounded-lg text-xs border border-zinc-200 text-zinc-700 dark:border-zinc-700 dark:text-zinc-300 disabled:opacity-50' },
      { action: 'move_to_front', label: 'Move to front', className: 'px-3 py-1.5 rounded-lg text-xs border border-sky-200 text-sky-700 dark:border-sky-900 dark:text-sky-300 disabled:opacity-50' },
      { action: 'start_now', label: 'Start now', className: 'px-3 py-1.5 rounded-lg text-xs border border-emerald-200 text-emerald-700 dark:border-emerald-900 dark:text-emerald-300 disabled:opacity-50' },
    ]
    actions.push(...queueActions.map((queueAction) => buildActionButton(
      `${scan.id}:${queueAction.action}`,
      queueAction.label,
      queueAction.className,
      isControlling,
      () => onQueueAction({ id: scan.id, action: queueAction.action }),
    )))
  }
  if (scan.status === 'paused') {
    actions.push(buildActionButton(
      `${scan.id}:resume`,
      'Resume now',
      'px-3 py-1.5 rounded-lg text-xs border border-emerald-200 text-emerald-700 dark:border-emerald-900 dark:text-emerald-300 disabled:opacity-50',
      isControlling,
      () => onControl({ id: scan.id, action: 'resume' }),
    ))
  }
  return actions
}

function formatPauseLabel(minutes: number): string {
  if (minutes < 60) return `${minutes}m`
  return `${minutes / 60}h`
}

function getScanDurationSeconds(scan: ScanJob): number | null {
  if (!scan.started_at || !scan.finished_at) {
    return null
  }
  return Math.round((new Date(scan.finished_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
}

function canExpandScan(status: ScanJob['status']): boolean {
  return ['pending', 'running', 'paused', 'failed', 'cancelled', 'done'].includes(status)
}

function readSummaryValue(summary: Record<string, unknown>, key: string, fallback: string) {
  const value = summary[key]
  if (typeof value === 'number' || typeof value === 'string') {
    return value
  }
  return fallback
}

function formatSummaryStage(summary: Record<string, unknown>): string | null {
  if (typeof summary.stage !== 'string') {
    return null
  }
  return summary.stage.replace('_', ' ')
}

function ProfileBadge({ profile }: Readonly<{ profile: string }>) {
  const colors: Record<string, string> = {
    quick:      'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
    polite:     'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
    balanced:   'bg-sky-500/10 text-sky-600 dark:text-sky-400',
    deep_enrichment: 'bg-red-500/10 text-red-600 dark:text-red-400',
    aggressive: 'bg-red-500/10 text-red-600 dark:text-red-400',
    custom:     'bg-zinc-500/10 text-zinc-600 dark:text-zinc-400',
  }
  const label = profile.replaceAll('_', ' ')
  return (
    <span className={`text-xs px-1.5 py-0.5 rounded font-medium capitalize ${colors[profile] ?? colors.custom}`}>
      {label || 'balanced'}
    </span>
  )
}

function ScanStatusBadge({ status }: Readonly<{ status: string }>) {
  const map: Record<string, { cls: string; dot?: string; label: string }> = {
    pending:  { cls: 'bg-zinc-500/10 text-zinc-500', dot: 'bg-zinc-400', label: 'Pending' },
    running:  { cls: 'bg-sky-500/10 text-sky-600 dark:text-sky-400', dot: 'bg-sky-500 animate-pulse', label: 'Running' },
    paused:   { cls: 'bg-amber-500/10 text-amber-600 dark:text-amber-400', dot: 'bg-amber-500', label: 'Paused' },
    cancelled:{ cls: 'bg-rose-500/10 text-rose-600 dark:text-rose-400', dot: 'bg-rose-500', label: 'Cancelled' },
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
