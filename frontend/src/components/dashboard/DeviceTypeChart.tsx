'use client'

import { useMemo } from 'react'
import { useDashboardAssets } from '@/hooks/useAssets'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'

const COLORS: Record<string, string> = {
  router: '#0ea5e9', switch: '#8b5cf6', access_point: '#06b6d4',
  server: '#22c55e', workstation: '#3b82f6', nas: '#14b8a6',
  printer: '#eab308', ip_camera: '#ec4899', smart_tv: '#a855f7',
  iot_device: '#f59e0b', firewall: '#f97316', voip: '#84cc16', unknown: '#71717a',
}

export function DeviceTypeChart() {
  const { data: assets = [], isLoading } = useDashboardAssets()

  const chartData = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const asset of assets) {
      const deviceClass = asset.ai_analysis?.device_class ?? asset.device_type ?? 'unknown'
      counts[deviceClass] = (counts[deviceClass] ?? 0) + 1
    }
    return Object.entries(counts)
      .map(([key, value]) => ({ key, name: key.replace(/_/g, ' '), value, fill: COLORS[key] ?? '#71717a' }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8)
  }, [assets])

  const total = chartData.reduce((s, d) => s + d.value, 0)

  const gradient = useMemo(() => {
    let offset = 0
    const stops = chartData.map((slice) => {
      const pct = total > 0 ? (slice.value / total) * 100 : 0
      const stop = `${slice.fill} ${offset.toFixed(2)}% ${(offset + pct).toFixed(2)}%`
      offset += pct
      return stop
    })
    return `conic-gradient(${stops.join(', ')})`
  }, [chartData, total])

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle>Device Types</CardTitle></CardHeader>
        <CardBody>
          <div className="h-48 flex items-center justify-center">
            <div className="w-32 h-32 rounded-full border-4 border-zinc-200 dark:border-zinc-800 border-t-sky-500 animate-spin" />
          </div>
        </CardBody>
      </Card>
    )
  }

  if (chartData.length === 0) {
    return (
      <Card>
        <CardHeader><CardTitle>Device Types</CardTitle></CardHeader>
        <CardBody>
          <div className="h-48 flex items-center justify-center text-zinc-400 text-sm">
            No data — run a scan first
          </div>
        </CardBody>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Device Types</CardTitle>
        <span className="text-xs text-zinc-500">{assets.length} total</span>
      </CardHeader>
      <CardBody>
        <div className="flex flex-col items-center gap-4">
          <div
            className="relative w-36 h-36 rounded-full flex-shrink-0"
            style={{ background: gradient }}
            role="img"
            aria-label="Device type distribution donut chart"
          >
            <div className="absolute inset-0 m-auto w-[60%] h-[60%] rounded-full bg-white dark:bg-zinc-900" />
          </div>
          <ul className="grid grid-cols-2 gap-x-4 gap-y-1.5 w-full text-xs">
            {chartData.map((slice) => (
              <li key={slice.key} className="flex items-center gap-1.5 min-w-0" title={`${slice.name}: ${slice.value}`}>
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: slice.fill }} />
                <span className="truncate text-zinc-600 dark:text-zinc-400">{slice.name}</span>
                <span className="ml-auto font-medium text-zinc-800 dark:text-zinc-200">{slice.value}</span>
              </li>
            ))}
          </ul>
        </div>
      </CardBody>
    </Card>
  )
}
