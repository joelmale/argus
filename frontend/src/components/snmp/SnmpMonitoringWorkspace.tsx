'use client'

import Link from 'next/link'
import { useState } from 'react'
import { ActivitySquare, Cpu, HardDrive, Network, RefreshCw, Router, Search } from 'lucide-react'
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/Card'
import { StatusBadge } from '@/components/ui/Badge'
import { useCurrentUser } from '@/hooks/useAuth'
import { useAssets, useRefreshAssetSnmp } from '@/hooks/useAssets'
import { cn, formatDate, timeAgo } from '@/lib/utils'
import type { AssetSummary, DeviceType, ProbeRun } from '@/types'

type SnmpResourceSummary = {
  cpuAverageLoad: number | null
  cpuCoreCount: number | null
  cpuLoads: number[]
  memoryLabel: string | null
  memoryTotalBytes: number | null
  memoryUsedBytes: number | null
  memoryUtilization: number | null
}

type SnmpInterface = {
  ifIndex: number | null
  name: string | null
  mac: string | null
  type: number | null
  speed: number | null
  highSpeedMbps: number | null
  adminStatus: number | null
  operStatus: number | null
  vlanId: number | null
  inOctetsTotal: number | null
  outOctetsTotal: number | null
  inErrors: number | null
  outErrors: number | null
}

type SnmpNeighbor = {
  protocol: string | null
  localPort: string | null
  remoteName: string | null
  remotePort: string | null
  remotePlatform: string | null
  remoteMac: string | null
}

type SnmpArpEntry = {
  ip: string | null
  mac: string | null
  ifIndex: number | null
}

type SnmpDetails = {
  sysDescr: string | null
  sysName: string | null
  sysObjectId: string | null
  sysLocation: string | null
  sysContact: string | null
  interfaces: SnmpInterface[]
  neighbors: SnmpNeighbor[]
  arpTable: SnmpArpEntry[]
  resourceSummary: SnmpResourceSummary
}

type SnmpAssetSummary = {
  asset: AssetSummary
  latestAttempt: ProbeRun | null
  latestSuccess: ProbeRun | null
  details: SnmpDetails | null
  managed: boolean
}

const EMPTY_RESOURCE_SUMMARY: SnmpResourceSummary = {
  cpuAverageLoad: null,
  cpuCoreCount: null,
  cpuLoads: [],
  memoryLabel: null,
  memoryTotalBytes: null,
  memoryUsedBytes: null,
  memoryUtilization: null,
}

const SNMP_AUTO_MANAGED_DEVICE_TYPES = new Set<DeviceType>([
  'router',
  'switch',
  'access_point',
  'firewall',
  'server',
  'nas',
  'printer',
  'voip',
])

const SNMP_HOSTNAME_HINTS = [
  'firewalla',
  'router',
  'gateway',
  'switch',
  'ap',
  'access-point',
  'accesspoint',
  'wifi',
  'unifi',
  'printer',
  'laserjet',
  'officejet',
  'deskjet',
  'ecotank',
  'mfc',
  'xerox',
  'canon',
  'epson',
  'nas',
  'synology',
  'truenas',
  'qnap',
  'proxmox',
  'esxi',
  'idrac',
  'ilo',
  'bmc',
  'ipmi',
  'yealink',
  'grandstream',
  'polycom',
]

const SNMP_VENDOR_HINTS = [
  'firewalla',
  'ubiquiti',
  'unifi',
  'cisco',
  'juniper',
  'aruba',
  'ruckus',
  'tp-link',
  'mikrotik',
  'netgate',
  'fortinet',
  'palo alto',
  'sonicwall',
  'watchguard',
  'synology',
  'qnap',
  'asustor',
  'hp',
  'hewlett',
  'brother',
  'epson',
  'canon',
  'xerox',
  'lexmark',
  'ricoh',
  'kyocera',
  'zebra',
  'dell',
  'idrac',
  'hpe',
  'ilo',
  'vmware',
  'proxmox',
  'yealink',
  'grandstream',
  'polycom',
]

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null
  }
  return value as Record<string, unknown>
}

function asString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function asRecordArray(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.map(asRecord).filter((item): item is Record<string, unknown> => item !== null)
}

function containsKeyword(value: string | null | undefined, keywords: string[]): boolean {
  const normalized = value?.trim().toLowerCase()
  if (!normalized) {
    return false
  }
  return keywords.some((keyword) => normalized.includes(keyword))
}

function parseSnmpDetails(probe: ProbeRun | null): SnmpDetails | null {
  const details = asRecord(probe?.details)
  if (!details) {
    return null
  }

  const resource = asRecord(details.resource_summary)
  return {
    sysDescr: asString(details.sys_descr),
    sysName: asString(details.sys_name),
    sysObjectId: asString(details.sys_object_id),
    sysLocation: asString(details.sys_location),
    sysContact: asString(details.sys_contact),
    interfaces: asRecordArray(details.interfaces).map((item) => ({
      ifIndex: asNumber(item.if_index),
      name: asString(item.name),
      mac: asString(item.mac),
      type: asNumber(item.type),
      speed: asNumber(item.speed),
      highSpeedMbps: asNumber(item.high_speed_mbps),
      adminStatus: asNumber(item.admin_status),
      operStatus: asNumber(item.oper_status),
      vlanId: asNumber(item.vlan_id),
      inOctetsTotal: asNumber(item.in_octets_total),
      outOctetsTotal: asNumber(item.out_octets_total),
      inErrors: asNumber(item.in_errors),
      outErrors: asNumber(item.out_errors),
    })),
    neighbors: asRecordArray(details.neighbors).map((item) => ({
      protocol: asString(item.protocol),
      localPort: valueToText(item.local_port),
      remoteName: asString(item.remote_name),
      remotePort: asString(item.remote_port),
      remotePlatform: asString(item.remote_platform),
      remoteMac: asString(item.remote_mac),
    })),
    arpTable: asRecordArray(details.arp_table).map((item) => ({
      ip: asString(item.ip),
      mac: asString(item.mac),
      ifIndex: asNumber(item.if_index),
    })),
    resourceSummary: {
      cpuAverageLoad: resource ? asNumber(resource.cpu_average_load) : null,
      cpuCoreCount: resource ? asNumber(resource.cpu_core_count) : null,
      cpuLoads: resource && Array.isArray(resource.cpu_loads)
        ? resource.cpu_loads.map((entry) => asNumber(entry)).filter((entry): entry is number => entry !== null)
        : [],
      memoryLabel: resource ? asString(resource.memory_label) : null,
      memoryTotalBytes: resource ? asNumber(resource.memory_total_bytes) : null,
      memoryUsedBytes: resource ? asNumber(resource.memory_used_bytes) : null,
      memoryUtilization: resource ? asNumber(resource.memory_utilization) : null,
    },
  }
}

function buildSnmpAssetSummary(asset: AssetSummary): SnmpAssetSummary {
  const snmpRuns = (asset.probe_runs ?? []).filter((probe) => probe.probe_type === 'snmp')
  const latestAttempt = snmpRuns[0] ?? null
  const latestSuccess = snmpRuns.find((probe) => probe.success) ?? null
  const hasOpenSnmpPort = (asset.ports ?? []).some((port) => port.port_number === 161 && port.state === 'open')
  const deviceTypes = [
    asset.device_type,
    asset.device_type_override,
    asset.ai_analysis?.device_class,
  ].filter((value): value is DeviceType => typeof value === 'string' && value.length > 0)
  const openPortSet = new Set(
    (asset.ports ?? [])
      .filter((port) => port.state === 'open')
      .map((port) => port.port_number),
  )
  const looksLikeManagedPrinter = (openPortSet.has(9100) || openPortSet.has(515) || openPortSet.has(631))
    && (openPortSet.has(80) || openPortSet.has(443) || openPortSet.has(8080) || openPortSet.has(8443))
  const looksLikeGateway = openPortSet.has(53) && (openPortSet.has(22) || openPortSet.has(80) || openPortSet.has(443))
  const looksLikeNas = openPortSet.has(445) && (openPortSet.has(2049) || openPortSet.has(548) || openPortSet.has(873))
  const likelyCandidate = deviceTypes.some((deviceType) => SNMP_AUTO_MANAGED_DEVICE_TYPES.has(deviceType))
    || containsKeyword(asset.hostname, SNMP_HOSTNAME_HINTS)
    || containsKeyword(asset.vendor, SNMP_VENDOR_HINTS)
    || containsKeyword(asset.ai_analysis?.vendor, SNMP_VENDOR_HINTS)
    || containsKeyword(asset.ai_analysis?.model, SNMP_HOSTNAME_HINTS)
    || containsKeyword(asset.ai_analysis?.device_role, SNMP_HOSTNAME_HINTS)
    || looksLikeManagedPrinter
    || looksLikeGateway
    || looksLikeNas

  return {
    asset,
    latestAttempt,
    latestSuccess,
    details: parseSnmpDetails(latestSuccess),
    managed: hasOpenSnmpPort || snmpRuns.length > 0 || likelyCandidate,
  }
}

function valueToText(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) {
    return value
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value)
  }
  return null
}

function formatBytes(value: number | null): string {
  if (value === null || value < 0) {
    return '—'
  }
  if (value < 1024) {
    return `${value} B`
  }
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let size = value
  let unitIndex = -1
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex += 1
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`
}

function formatBitsPerSecond(value: number | null): string {
  if (value === null || value <= 0) {
    return '—'
  }
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']
  let size = value
  let unitIndex = 0
  while (size >= 1000 && unitIndex < units.length - 1) {
    size /= 1000
    unitIndex += 1
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`
}

function formatPercent(value: number | null): string {
  if (value === null) {
    return '—'
  }
  const normalized = value <= 1 ? value * 100 : value
  return `${normalized.toFixed(normalized >= 10 ? 0 : 1)}%`
}

function formatInterfaceSpeed(item: SnmpInterface): string {
  if (item.highSpeedMbps && item.highSpeedMbps > 0) {
    if (item.highSpeedMbps >= 1000) {
      return `${(item.highSpeedMbps / 1000).toFixed(item.highSpeedMbps >= 10000 ? 0 : 1)} Gbps`
    }
    return `${item.highSpeedMbps} Mbps`
  }
  return formatBitsPerSecond(item.speed)
}

function formatInterfaceState(value: number | null): string {
  if (value === 1) return 'up'
  if (value === 2) return 'down'
  if (value === 3) return 'testing'
  return '—'
}

function buildSearchText(summary: SnmpAssetSummary): string {
  return [
    summary.asset.ip_address,
    summary.asset.hostname,
    summary.asset.vendor,
    summary.asset.device_type,
    summary.asset.ai_analysis?.vendor,
    summary.asset.ai_analysis?.model,
    summary.asset.ai_analysis?.device_role,
    summary.details?.sysName,
    summary.details?.sysDescr,
    summary.details?.sysObjectId,
  ]
    .filter((value): value is string => typeof value === 'string' && value.length > 0)
    .join(' ')
    .toLowerCase()
}

function extractProbeError(probe: ProbeRun | null): string | null {
  const details = asRecord(probe?.details)
  return asString(details?.error) || asString(probe?.summary) || asString(probe?.raw_excerpt)
}

function renderMetric(label: string, value: string, helper?: string) {
  return (
    <div>
      <p className="text-xs text-zinc-500">{label}</p>
      <p className="text-sm text-zinc-900 dark:text-zinc-100 break-words">{value}</p>
      {helper && <p className="text-[11px] text-zinc-400 mt-1">{helper}</p>}
    </div>
  )
}

function DetailsTable({
  headers,
  rows,
}: Readonly<{
  headers: string[]
  rows: string[][]
}>) {
  if (rows.length === 0) {
    return <p className="text-sm text-zinc-500">No data recorded in the latest successful SNMP poll.</p>
  }

  return (
    <div className="max-h-96 overflow-auto rounded-xl border border-gray-200 dark:border-zinc-800">
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-white dark:bg-zinc-950">
          <tr className="border-b border-gray-100 dark:border-zinc-800">
            {headers.map((header) => (
              <th key={header} className="px-4 py-2 text-left text-[11px] uppercase tracking-wider text-zinc-500 font-medium">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
          {rows.map((row, index) => (
            <tr key={`${row.join('|')}:${index}`} className="align-top">
              {row.map((cell, cellIndex) => (
                <td key={`${headers[cellIndex]}:${cell}`} className="px-4 py-2 text-zinc-700 dark:text-zinc-300">
                  {cell || '—'}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SnmpMonitoringWorkspace() {
  const { data: assets = [], isLoading, isError } = useAssets({ include: ['ports', 'ai', 'probe_runs'] })
  const { data: currentUser } = useCurrentUser()
  const { mutate: refreshSnmp, isPending: isRefreshing } = useRefreshAssetSnmp()
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [refreshMessage, setRefreshMessage] = useState<string | null>(null)

  const summaries = assets
    .map(buildSnmpAssetSummary)
    .filter((summary) => summary.managed)
    .sort((left, right) => {
      const leftTime = left.latestSuccess ? new Date(left.latestSuccess.observed_at).getTime() : 0
      const rightTime = right.latestSuccess ? new Date(right.latestSuccess.observed_at).getTime() : 0
      if (leftTime !== rightTime) {
        return rightTime - leftTime
      }
      return left.asset.ip_address.localeCompare(right.asset.ip_address)
    })

  const normalizedSearch = search.trim().toLowerCase()
  const filteredSummaries = normalizedSearch
    ? summaries.filter((summary) => buildSearchText(summary).includes(normalizedSearch))
    : summaries

  const selectedSummary = filteredSummaries.find((summary) => summary.asset.id === selectedAssetId) ?? filteredSummaries[0] ?? null
  const selectedDetails = selectedSummary?.details ?? null
  const resourceSummary = selectedDetails?.resourceSummary ?? EMPTY_RESOURCE_SUMMARY
  const hasResourceSummary = resourceSummary.cpuAverageLoad !== null || resourceSummary.memoryTotalBytes !== null

  const successfulPolls = summaries.filter((summary) => summary.latestSuccess).length
  const respondingAssets = summaries.filter((summary) => summary.asset.status === 'online').length
  const resourceAwareAssets = summaries.filter((summary) => {
    const resource = summary.details?.resourceSummary
    return Boolean(resource && (resource.cpuAverageLoad !== null || resource.memoryTotalBytes !== null))
  }).length

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-xl font-semibold text-zinc-900 dark:text-white">SNMP Monitoring</h2>
          <p className="mt-1 text-sm text-zinc-500">
            Central view for assets that expose SNMP. Latest successful poll data stays here instead of crowding the asset detail page.
          </p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Card>
            <CardBody className="py-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500">Managed assets</p>
              <p className="mt-1 text-2xl font-semibold tabular text-zinc-900 dark:text-white">{summaries.length}</p>
            </CardBody>
          </Card>
          <Card>
            <CardBody className="py-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500">Successful polls</p>
              <p className="mt-1 text-2xl font-semibold tabular text-zinc-900 dark:text-white">{successfulPolls}</p>
            </CardBody>
          </Card>
          <Card>
            <CardBody className="py-4">
              <p className="text-xs uppercase tracking-wider text-zinc-500">Resource aware</p>
              <p className="mt-1 text-2xl font-semibold tabular text-zinc-900 dark:text-white">{resourceAwareAssets}</p>
            </CardBody>
          </Card>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-4 space-y-5">
          <Card>
            <CardHeader>
              <CardTitle><Search className="w-4 h-4 inline mr-1.5" />SNMP Asset List</CardTitle>
            </CardHeader>
            <CardBody className="space-y-4">
              <div className="rounded-xl border border-gray-200 dark:border-zinc-800 px-3 py-2 flex items-center gap-2">
                <Search className="w-4 h-4 text-zinc-400" />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search IP, hostname, vendor, sysName, sysDescr"
                  className="w-full bg-transparent text-sm outline-none placeholder:text-zinc-400"
                />
              </div>
              {isLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 5 }, (_, index) => (
                    <div key={`snmp-loading-${index}`} className="h-20 rounded-xl bg-zinc-200 dark:bg-zinc-900 animate-pulse" />
                  ))}
                </div>
              ) : isError ? (
                <p className="text-sm text-red-500">Unable to load SNMP-monitored assets.</p>
              ) : filteredSummaries.length === 0 ? (
                <p className="text-sm text-zinc-500">
                  No assets with SNMP signal were found. A device appears here after port `161/udp` is discovered or an SNMP probe has run.
                </p>
              ) : (
                <div className="space-y-3">
                  {filteredSummaries.map((summary) => {
                    const isSelected = summary.asset.id === selectedSummary?.asset.id
                    return (
                      <button
                        key={summary.asset.id}
                        type="button"
                        onClick={() => {
                          setSelectedAssetId(summary.asset.id)
                          setRefreshMessage(null)
                        }}
                        className={cn(
                          'w-full rounded-2xl border p-4 text-left transition-colors',
                          isSelected
                            ? 'border-sky-500/40 bg-sky-50 dark:bg-sky-500/10'
                            : 'border-gray-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-900/70',
                        )}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="font-mono text-sm font-medium text-zinc-900 dark:text-zinc-100">{summary.asset.ip_address}</p>
                            <p className="text-xs text-zinc-500 mt-1">
                              {summary.asset.hostname || 'Unnamed asset'} · {summary.asset.vendor || summary.asset.device_type || 'unknown'}
                            </p>
                          </div>
                          <StatusBadge status={summary.asset.status} />
                        </div>
                        <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-zinc-500">
                          <div>
                            <p className="uppercase tracking-wider text-[10px]">Last success</p>
                            <p className="mt-1 text-zinc-700 dark:text-zinc-300">
                              {summary.latestSuccess ? timeAgo(summary.latestSuccess.observed_at) : 'Never'}
                            </p>
                          </div>
                          <div>
                            <p className="uppercase tracking-wider text-[10px]">Live status</p>
                            <p className="mt-1 text-zinc-700 dark:text-zinc-300">
                              {summary.asset.status === 'online' ? 'Responding' : 'Needs attention'}
                            </p>
                          </div>
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}
              <div className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 text-xs text-zinc-500">
                <p>{respondingAssets} of {summaries.length} SNMP-tracked assets are currently online.</p>
              </div>
            </CardBody>
          </Card>
        </div>

        <div className="xl:col-span-8 space-y-5">
          {!selectedSummary ? (
            <Card>
              <CardBody className="py-12">
                <p className="text-center text-sm text-zinc-500">Select an SNMP asset to inspect its latest poll data.</p>
              </CardBody>
            </Card>
          ) : (
            <>
              <Card>
                <CardHeader>
                  <div className="flex items-start justify-between gap-4 flex-wrap">
                    <div>
                      <CardTitle><Router className="w-4 h-4 inline mr-1.5" />{selectedSummary.asset.ip_address}</CardTitle>
                      <p className="mt-1 text-sm text-zinc-500">
                        {selectedSummary.asset.hostname || 'Unnamed asset'} · {selectedSummary.asset.vendor || selectedSummary.asset.device_type || 'unknown vendor'}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Link
                        href={`/assets/${selectedSummary.asset.id}`}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-gray-200 dark:border-zinc-700"
                      >
                        Open asset
                      </Link>
                      {currentUser?.role === 'admin' && (
                        <button
                          type="button"
                          onClick={() => {
                            setRefreshMessage(null)
                            refreshSnmp(selectedSummary.asset.id, {
                              onSuccess: () => {
                                setRefreshMessage(`SNMP refresh completed for ${selectedSummary.asset.ip_address}.`)
                              },
                              onError: (error: any) => {
                                const detail = error?.response?.data?.detail
                                setRefreshMessage(
                                  typeof detail === 'string'
                                    ? `SNMP refresh failed: ${detail}`
                                    : `SNMP refresh failed for ${selectedSummary.asset.ip_address}.`,
                                )
                              },
                            })
                          }}
                          disabled={isRefreshing}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-sky-500 text-white disabled:bg-zinc-300 disabled:text-zinc-500 dark:disabled:bg-zinc-800"
                        >
                          <RefreshCw className={cn('w-3.5 h-3.5', isRefreshing && 'animate-spin')} />
                          {isRefreshing ? 'Polling…' : 'Refresh SNMP'}
                        </button>
                      )}
                    </div>
                  </div>
                  {refreshMessage && <p className="text-xs text-zinc-500 mt-3">{refreshMessage}</p>}
                </CardHeader>
                <CardBody className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                    {renderMetric('Last successful poll', selectedSummary.latestSuccess ? formatDate(selectedSummary.latestSuccess.observed_at) : 'Never')}
                    {renderMetric('Latest attempt', selectedSummary.latestAttempt ? formatDate(selectedSummary.latestAttempt.observed_at) : 'Never', selectedSummary.latestAttempt ? (selectedSummary.latestAttempt.success ? 'success' : 'failed') : undefined)}
                    {renderMetric('sysName', selectedDetails?.sysName || '—')}
                    {renderMetric('sysObjectID', selectedDetails?.sysObjectId || '—')}
                    {renderMetric('sysDescr', selectedDetails?.sysDescr || '—')}
                    {renderMetric('sysLocation', selectedDetails?.sysLocation || '—')}
                    {renderMetric('sysContact', selectedDetails?.sysContact || '—')}
                    {renderMetric('Current asset status', selectedSummary.asset.status)}
                  </div>
                  {selectedSummary.latestAttempt && !selectedSummary.latestAttempt.success && !selectedSummary.latestSuccess && (
                    <div className="rounded-xl border border-amber-200 bg-amber-50 dark:border-amber-900/50 dark:bg-amber-900/10 p-4 text-sm text-amber-700 dark:text-amber-300">
                      Argus has attempted SNMP for this asset, but no successful poll has been stored yet. Check credentials, version, reachability, and whether the device exposes standard OIDs.
                    </div>
                  )}
                </CardBody>
              </Card>

                  {hasResourceSummary && (
                <Card>
                  <CardHeader>
                    <CardTitle><Cpu className="w-4 h-4 inline mr-1.5" />Resource Summary</CardTitle>
                  </CardHeader>
                  <CardBody className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
                    {renderMetric('CPU average load', formatPercent(resourceSummary.cpuAverageLoad))}
                    {renderMetric('CPU cores reported', valueToText(resourceSummary.cpuCoreCount) || '—', resourceSummary.cpuLoads.length > 0 ? resourceSummary.cpuLoads.join('% / ') + '%' : undefined)}
                    {renderMetric('Memory used', formatBytes(resourceSummary.memoryUsedBytes))}
                    {renderMetric('Memory total', formatBytes(resourceSummary.memoryTotalBytes), resourceSummary.memoryLabel || undefined)}
                    {renderMetric('Memory utilization', formatPercent(resourceSummary.memoryUtilization))}
                  </CardBody>
                </Card>
              )}

              <Card>
                <CardHeader>
                  <CardTitle><ActivitySquare className="w-4 h-4 inline mr-1.5" />Interfaces & VLANs</CardTitle>
                </CardHeader>
                <CardBody className="space-y-3">
                  <div className="text-xs text-zinc-500">
                    {selectedDetails?.interfaces.length ?? 0} interfaces captured in the latest successful poll.
                  </div>
                  <DetailsTable
                    headers={['IfIndex', 'Name', 'State', 'VLAN', 'Speed', 'Traffic', 'Errors', 'MAC']}
                    rows={(selectedDetails?.interfaces ?? []).map((item) => [
                      valueToText(item.ifIndex) || '—',
                      item.name || '—',
                      `${formatInterfaceState(item.adminStatus)} / ${formatInterfaceState(item.operStatus)}`,
                      valueToText(item.vlanId) || '—',
                      formatInterfaceSpeed(item),
                      `${formatBytes(item.inOctetsTotal)} in / ${formatBytes(item.outOctetsTotal)} out`,
                      `${valueToText(item.inErrors) || '0'} in / ${valueToText(item.outErrors) || '0'} out`,
                      item.mac || '—',
                    ])}
                  />
                </CardBody>
              </Card>

              <div className="grid grid-cols-1 2xl:grid-cols-2 gap-5">
                <Card>
                  <CardHeader>
                    <CardTitle><Network className="w-4 h-4 inline mr-1.5" />LLDP / CDP Neighbors</CardTitle>
                  </CardHeader>
                  <CardBody className="space-y-3">
                    <div className="text-xs text-zinc-500">
                      {selectedDetails?.neighbors.length ?? 0} layer-2 neighbors captured in the latest successful poll.
                    </div>
                    <DetailsTable
                      headers={['Protocol', 'Local port', 'Remote name', 'Remote port', 'Platform', 'Remote MAC']}
                      rows={(selectedDetails?.neighbors ?? []).map((item) => [
                        item.protocol || '—',
                        item.localPort || '—',
                        item.remoteName || '—',
                        item.remotePort || '—',
                        item.remotePlatform || '—',
                        item.remoteMac || '—',
                      ])}
                    />
                  </CardBody>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle><HardDrive className="w-4 h-4 inline mr-1.5" />ARP Entries</CardTitle>
                  </CardHeader>
                  <CardBody className="space-y-3">
                    <div className="text-xs text-zinc-500">
                      {selectedDetails?.arpTable.length ?? 0} ARP entries captured in the latest successful poll.
                    </div>
                    <DetailsTable
                      headers={['IP', 'MAC', 'IfIndex']}
                      rows={(selectedDetails?.arpTable ?? []).map((item) => [
                        item.ip || '—',
                        item.mac || '—',
                        valueToText(item.ifIndex) || '—',
                      ])}
                    />
                  </CardBody>
                </Card>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
