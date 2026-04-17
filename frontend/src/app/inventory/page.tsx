'use client'

import type React from 'react'
import Link from 'next/link'
import {
  Activity,
  MonitorDot,
  Network,
  Server,
} from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/Card'
import { useAssetInventory, useAssetStats } from '@/hooks/useAssets'
import type { InventoryCountRow, InventoryPortRow, InventoryVersionRow } from '@/hooks/useAssets'
import { cn } from '@/lib/utils'

// ─── Colour palettes ────────────────────────────────────────────────────────

const BAR_COLORS = [
  'bg-sky-500',
  'bg-emerald-500',
  'bg-amber-500',
  'bg-violet-500',
  'bg-cyan-500',
  'bg-rose-500',
  'bg-orange-500',
  'bg-teal-500',
  'bg-indigo-500',
  'bg-pink-500',
]

const SERVICE_COLORS: Record<string, string> = {
  http:     'bg-sky-500',
  https:    'bg-emerald-500',
  ssh:      'bg-violet-500',
  ftp:      'bg-amber-500',
  smtp:     'bg-orange-500',
  dns:      'bg-cyan-500',
  snmp:     'bg-teal-500',
  smb:      'bg-rose-500',
  rdp:      'bg-indigo-500',
  telnet:   'bg-red-500',
}

function serviceColor(name: string | null, idx: number): string {
  if (name) {
    const key = name.toLowerCase()
    if (SERVICE_COLORS[key]) return SERVICE_COLORS[key]
  }
  return BAR_COLORS[idx % BAR_COLORS.length]
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatDeviceType(raw: string): string {
  return raw.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function normalizeOsLabel(raw: string): string {
  const v = raw.toLowerCase()
  if (v.includes('windows')) return 'Windows'
  if (v.includes('mac os') || v.includes('macos') || v.includes('os x')) return 'macOS'
  if (v.includes('android')) return 'Android'
  if (v.includes('ios') && !v.includes('cisco')) return 'iOS'
  if (v.includes('chrome os') || v.includes('chromium os')) return 'ChromeOS'
  if (
    v.includes('linux') || v.includes('ubuntu') || v.includes('debian') ||
    v.includes('fedora') || v.includes('centos') || v.includes('red hat') ||
    v.includes('rocky') || v.includes('alma') || v.includes('suse') || v.includes('raspbian')
  ) return 'Linux'
  if (v.includes('routeros')) return 'RouterOS'
  if (v.includes('cisco ios')) return 'Cisco IOS'
  if (v.includes('fortios')) return 'FortiOS'
  if (v.includes('junos')) return 'Junos'
  if (v.includes('openwrt')) return 'OpenWrt'
  if (v.includes('freebsd')) return 'FreeBSD'
  return raw
}

/** Bucket raw OS names into normalised groups and sum counts. */
function bucketOsCounts(rows: InventoryCountRow[]): InventoryCountRow[] {
  const map = new Map<string, number>()
  for (const row of rows) {
    const label = normalizeOsLabel(row.label)
    map.set(label, (map.get(label) ?? 0) + row.count)
  }
  return [...map.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
}

// ─── Sub-components ─────────────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  iconBg,
  isLoading,
}: {
  icon: React.ElementType
  label: string
  value: number | string
  sub?: string
  iconBg: string
  isLoading: boolean
}) {
  return (
    <Card>
      <CardBody className="flex items-start gap-4">
        <div className={cn('w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0', iconBg)}>
          <Icon className="w-5 h-5 text-white" />
        </div>
        <div className="min-w-0">
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">{label}</p>
          {isLoading ? (
            <div className="h-7 w-16 bg-zinc-200 dark:bg-zinc-800 rounded animate-pulse" />
          ) : (
            <p className="text-2xl font-bold tabular text-zinc-900 dark:text-white">{value}</p>
          )}
          {sub && <p className="text-xs text-zinc-400 mt-0.5">{sub}</p>}
        </div>
      </CardBody>
    </Card>
  )
}

/** Horizontal bar chart row */
function BarRow({
  label,
  count,
  total,
  colorClass,
  href,
}: {
  label: string
  count: number
  total: number
  colorClass: string
  href?: string
}) {
  const pct = total > 0 ? (count / total) * 100 : 0
  const labelEl = href ? (
    <Link href={href} className="font-medium text-zinc-900 dark:text-white hover:text-sky-500 dark:hover:text-sky-400 transition-colors truncate">
      {label}
    </Link>
  ) : (
    <span className="font-medium text-zinc-900 dark:text-white truncate">{label}</span>
  )

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-3 text-sm">
        {labelEl}
        <span className="text-zinc-500 flex-shrink-0 tabular">
          {count} · {Math.round(pct)}%
        </span>
      </div>
      <div className="h-2 rounded-full bg-zinc-100 dark:bg-zinc-800">
        <div
          className={cn('h-2 rounded-full transition-[width] duration-500', colorClass)}
          style={{ width: `${pct}%`, minWidth: '0.5rem' }}
        />
      </div>
    </div>
  )
}

function BarListCard({
  title,
  subtitle,
  rows,
  isLoading,
  emptyText,
  labelHref,
  maxRows = 10,
}: {
  title: string
  subtitle?: string
  rows: { label: string; count: number; colorClass: string; href?: string }[]
  isLoading: boolean
  emptyText: string
  labelHref?: (label: string) => string
  maxRows?: number
}) {
  const total = rows.reduce((s, r) => s + r.count, 0)
  const visible = rows.slice(0, maxRows)

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {subtitle && <span className="text-xs text-zinc-500">{subtitle}</span>}
      </CardHeader>
      <CardBody>
        {isLoading ? (
          <div className="space-y-4">
            {Array.from({ length: 5 }, (_, i) => (
              <div key={i} className="space-y-2">
                <div className="h-3 w-32 rounded bg-zinc-100 dark:bg-zinc-800 animate-pulse" />
                <div className="h-2 rounded-full bg-zinc-100 dark:bg-zinc-800 animate-pulse" />
              </div>
            ))}
          </div>
        ) : visible.length === 0 ? (
          <p className="text-sm text-zinc-400 py-8 text-center">{emptyText}</p>
        ) : (
          <div className="space-y-3">
            {visible.map((row, i) => (
              <BarRow
                key={row.label + i}
                label={row.label}
                count={row.count}
                total={total}
                colorClass={row.colorClass}
                href={labelHref ? labelHref(row.label) : row.href}
              />
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  )
}

/** Port table */
function PortsCard({
  ports,
  isLoading,
}: {
  ports: InventoryPortRow[]
  isLoading: boolean
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Top Open Ports</CardTitle>
        <span className="text-xs text-zinc-500">{ports.length} shown</span>
      </CardHeader>
      <div className="overflow-x-auto">
        {isLoading ? (
          <div className="px-5 py-4 space-y-3">
            {Array.from({ length: 6 }, (_, i) => (
              <div key={i} className="h-8 rounded bg-zinc-100 dark:bg-zinc-800 animate-pulse" />
            ))}
          </div>
        ) : ports.length === 0 ? (
          <p className="text-sm text-zinc-400 py-10 text-center px-5">
            No open ports discovered yet — run a scan to populate this data.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 dark:border-zinc-800">
                <th className="px-5 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Port</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Proto</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Service</th>
                <th className="px-5 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Assets</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
              {ports.map((p, i) => (
                <tr
                  key={`${p.port}-${p.protocol}-${i}`}
                  className="hover:bg-gray-50 dark:hover:bg-zinc-800/50 transition-colors"
                >
                  <td className="px-5 py-3">
                    <span className="font-mono font-semibold text-zinc-900 dark:text-white tabular">
                      {p.port}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <span className="inline-flex px-2 py-0.5 rounded-full text-xs font-medium border bg-zinc-500/10 text-zinc-600 dark:text-zinc-300 border-zinc-500/20">
                      {p.protocol.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-zinc-700 dark:text-zinc-300">
                    {p.service ? (
                      <Link
                        href={`/assets?search=${encodeURIComponent(p.service)}`}
                        className="hover:text-sky-500 transition-colors"
                      >
                        {p.service}
                      </Link>
                    ) : (
                      <span className="text-zinc-400 italic">unknown</span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-right tabular text-zinc-900 dark:text-white font-medium">
                    {p.asset_count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Card>
  )
}

/** Software versions table */
function VersionsCard({
  versions,
  isLoading,
}: {
  versions: InventoryVersionRow[]
  isLoading: boolean
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Software Versions Detected</CardTitle>
        <span className="text-xs text-zinc-500">{versions.length} shown</span>
      </CardHeader>
      <div className="overflow-x-auto">
        {isLoading ? (
          <div className="px-5 py-4 space-y-3">
            {Array.from({ length: 6 }, (_, i) => (
              <div key={i} className="h-8 rounded bg-zinc-100 dark:bg-zinc-800 animate-pulse" />
            ))}
          </div>
        ) : versions.length === 0 ? (
          <p className="text-sm text-zinc-400 py-10 text-center px-5">
            No software version data yet — run a scan with banner grabbing enabled.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 dark:border-zinc-800">
                <th className="px-5 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Service</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider">Version</th>
                <th className="px-5 py-3 text-right text-xs font-medium text-zinc-500 uppercase tracking-wider">Assets</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
              {versions.map((v, i) => (
                <tr
                  key={`${v.service}-${v.version}-${i}`}
                  className="hover:bg-gray-50 dark:hover:bg-zinc-800/50 transition-colors"
                >
                  <td className="px-5 py-3 text-zinc-700 dark:text-zinc-300 font-medium">
                    {v.service}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-zinc-600 dark:text-zinc-400">
                    {v.version}
                  </td>
                  <td className="px-5 py-3 text-right tabular text-zinc-900 dark:text-white font-medium">
                    {v.asset_count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Card>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function InventoryPage() {
  const { data: inv, isLoading } = useAssetInventory()
  const { total, online, offline, isLoading: statsLoading } = useAssetStats()

  // Build bar-chart rows for OS
  const osBuckets = bucketOsCounts(inv?.os_counts ?? [])
  const osRows = osBuckets.map((r, i) => ({
    label: r.label,
    count: r.count,
    colorClass: BAR_COLORS[i % BAR_COLORS.length],
    href: `/assets?search=${encodeURIComponent(r.label)}`,
  }))

  // Device type rows
  const deviceRows = (inv?.device_type_counts ?? []).map((r, i) => ({
    label: formatDeviceType(r.label),
    count: r.count,
    colorClass: BAR_COLORS[i % BAR_COLORS.length],
    href: `/assets?search=${encodeURIComponent(r.label)}`,
  }))

  // Vendor rows
  const vendorRows = (inv?.vendor_counts ?? []).map((r, i) => ({
    label: r.label,
    count: r.count,
    colorClass: BAR_COLORS[i % BAR_COLORS.length],
  }))

  // Service rows
  const serviceRows = (inv?.top_services ?? []).map((r, i) => ({
    label: r.service,
    count: r.asset_count,
    colorClass: serviceColor(r.service, i),
    href: `/assets?search=${encodeURIComponent(r.service)}`,
  }))

  const anyLoading = isLoading || statsLoading

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-6">

        {/* Page heading */}
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Inventory</h2>
          <p className="text-sm text-zinc-500 mt-0.5">
            A bird&apos;s-eye view of everything discovered on your network.
          </p>
        </div>

        {/* ── Stat strip ───────────────────────────────────────────── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            icon={Server}
            label="Total Assets"
            value={total || inv?.total_assets || 0}
            iconBg="bg-sky-500"
            isLoading={anyLoading}
          />
          <StatCard
            icon={Activity}
            label="Online"
            value={online}
            iconBg="bg-emerald-500"
            isLoading={anyLoading}
          />
          <StatCard
            icon={MonitorDot}
            label="Offline"
            value={offline}
            iconBg="bg-red-500"
            isLoading={anyLoading}
          />
          <StatCard
            icon={Network}
            label="Open Ports"
            value={inv?.total_open_ports ?? 0}
            sub="across all assets"
            iconBg="bg-violet-500"
            isLoading={anyLoading}
          />
        </div>

        {/* ── OS + Device type + Vendor ─────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <BarListCard
            title="Operating Systems"
            subtitle={`${osBuckets.length} detected`}
            rows={osRows}
            isLoading={isLoading}
            emptyText="No OS data yet — run a scan to discover OS information."
            maxRows={12}
          />
          <BarListCard
            title="Device Types"
            subtitle={`${deviceRows.length} types`}
            rows={deviceRows}
            isLoading={isLoading}
            emptyText="No device type data yet."
            maxRows={12}
          />
          <BarListCard
            title="Hardware Vendors"
            subtitle="by MAC OUI"
            rows={vendorRows}
            isLoading={isLoading}
            emptyText="No vendor data yet — MAC addresses required."
            maxRows={12}
          />
        </div>

        {/* ── Services + Ports ─────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <BarListCard
            title="Services Listening"
            subtitle="by how many assets expose them"
            rows={serviceRows}
            isLoading={isLoading}
            emptyText="No service data yet — run a port scan to populate this."
            maxRows={15}
          />
          <PortsCard ports={inv?.top_ports ?? []} isLoading={isLoading} />
        </div>

        {/* ── Software versions ─────────────────────────────────────── */}
        <VersionsCard versions={inv?.top_versions ?? []} isLoading={isLoading} />

      </div>
    </AppShell>
  )
}
