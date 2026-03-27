'use client'

import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/Card'
import { useAssets } from '@/hooks/useAssets'
import type { Asset } from '@/types'

const MAX_BUCKETS = 6
const BAR_COLORS = [
  'bg-sky-500',
  'bg-emerald-500',
  'bg-amber-500',
  'bg-violet-500',
  'bg-cyan-500',
  'bg-rose-500',
]

type OsBucket = {
  label: string
  value: number
  percent: number
  barClassName: string
}

function getAssetOs(asset: Asset): string | null {
  return asset.os_name ?? asset.ai_analysis?.os_guess ?? null
}

function normalizeOsLabel(rawValue: string | null): string {
  const value = rawValue?.trim()
  if (!value) {
    return 'Unknown'
  }

  const normalized = value.toLowerCase()
  if (normalized.includes('windows')) return 'Windows'
  if (normalized.includes('mac os') || normalized.includes('macos') || normalized.includes('os x')) return 'macOS'
  if (normalized.includes('ios') && !normalized.includes('cisco')) return 'iOS'
  if (normalized.includes('android')) return 'Android'
  if (normalized.includes('chrome os') || normalized.includes('chromium os')) return 'ChromeOS'
  if (
    normalized.includes('linux')
    || normalized.includes('ubuntu')
    || normalized.includes('debian')
    || normalized.includes('fedora')
    || normalized.includes('centos')
    || normalized.includes('red hat')
    || normalized.includes('rocky')
    || normalized.includes('alma')
    || normalized.includes('suse')
    || normalized.includes('raspbian')
  ) return 'Linux'
  if (normalized.includes('routeros')) return 'RouterOS'
  if (normalized.includes('cisco ios')) return 'Cisco IOS'
  if (normalized.includes('fortios')) return 'FortiOS'
  if (normalized.includes('junos')) return 'Junos'
  if (normalized.includes('openwrt')) return 'OpenWrt'
  if (normalized.includes('freebsd')) return 'FreeBSD'

  return value
}

function buildBuckets(assets: Asset[]): OsBucket[] {
  if (assets.length === 0) {
    return []
  }

  const counts = new Map<string, number>()
  for (const asset of assets) {
    const label = normalizeOsLabel(getAssetOs(asset))
    counts.set(label, (counts.get(label) ?? 0) + 1)
  }

  const sortedBuckets = [...counts.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label))

  const visibleBuckets = sortedBuckets.length > MAX_BUCKETS
    ? [
        ...sortedBuckets.slice(0, MAX_BUCKETS - 1),
        {
          label: 'Other',
          value: sortedBuckets.slice(MAX_BUCKETS - 1).reduce((total, bucket) => total + bucket.value, 0),
        },
      ]
    : sortedBuckets

  return visibleBuckets.map((bucket, index) => ({
    ...bucket,
    percent: (bucket.value / assets.length) * 100,
    barClassName: BAR_COLORS[index % BAR_COLORS.length],
  }))
}

export function OsCompositionWidget() {
  const { data: assets = [], isLoading } = useAssets()
  const buckets = buildBuckets(assets)
  const identifiedCount = assets.filter((asset) => normalizeOsLabel(getAssetOs(asset)) !== 'Unknown').length

  function renderBody() {
    if (isLoading) {
      return (
        <div className="space-y-4">
          <div className="h-12 rounded-xl bg-zinc-100 dark:bg-zinc-800 animate-pulse" />
          <div className="space-y-3">
            {Array.from({ length: 5 }, (_, index) => (
              <div key={`os-widget-skeleton-${index}`} className="space-y-2">
                <div className="h-3 w-24 rounded bg-zinc-100 dark:bg-zinc-800 animate-pulse" />
                <div className="h-2 rounded-full bg-zinc-100 dark:bg-zinc-800 animate-pulse" />
              </div>
            ))}
          </div>
        </div>
      )
    }

    if (buckets.length === 0) {
      return (
        <div className="flex h-64 items-center justify-center text-sm text-zinc-400">
          No assets yet — trigger a scan to discover OS data
        </div>
      )
    }

    return (
      <div className="space-y-5">
        <div className="rounded-xl border border-gray-200 bg-zinc-50/80 px-4 py-3 dark:border-zinc-800 dark:bg-zinc-950/50">
          <p className="text-xs uppercase tracking-[0.18em] text-zinc-500">Coverage</p>
          <div className="mt-2 flex items-end justify-between gap-3">
            <div>
              <p className="text-2xl font-semibold text-zinc-900 dark:text-white">
                {assets.length === 0 ? 0 : Math.round((identifiedCount / assets.length) * 100)}%
              </p>
              <p className="text-xs text-zinc-500">
                {identifiedCount} of {assets.length} assets have an OS classification
              </p>
            </div>
            <p className="text-right text-xs text-zinc-500">
              Stored OS name
              <br />
              falls back to AI guess
            </p>
          </div>
        </div>

        <div className="space-y-3">
          {buckets.map((bucket) => (
            <div key={bucket.label} className="space-y-1.5">
              <div className="flex items-center justify-between gap-3 text-sm">
                <span className="font-medium text-zinc-900 dark:text-white">{bucket.label}</span>
                <span className="text-zinc-500">
                  {bucket.value} · {Math.round(bucket.percent)}%
                </span>
              </div>
              <div className="h-2 rounded-full bg-zinc-100 dark:bg-zinc-800">
                <div
                  className={`h-2 rounded-full transition-[width] duration-500 ${bucket.barClassName}`}
                  style={{ width: `${bucket.percent}%`, minWidth: '0.75rem' }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>OS Makeup</CardTitle>
        <span className="text-xs text-zinc-500">{assets.length} total</span>
      </CardHeader>
      <CardBody>{renderBody()}</CardBody>
    </Card>
  )
}
