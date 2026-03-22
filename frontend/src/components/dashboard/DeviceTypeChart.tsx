'use client'

import { useMemo } from 'react'
import { PieChart, Pie, Sector, Tooltip, ResponsiveContainer, Legend, type PieSectorDataItem } from 'recharts'
import { useAssets } from '@/hooks/useAssets'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'

const COLORS: Record<string, string> = {
  router: '#0ea5e9', switch: '#8b5cf6', access_point: '#06b6d4',
  server: '#22c55e', workstation: '#3b82f6', nas: '#14b8a6',
  printer: '#eab308', ip_camera: '#ec4899', smart_tv: '#a855f7',
  iot_device: '#f59e0b', firewall: '#f97316', voip: '#84cc16', unknown: '#71717a',
}

function renderChartSector(props: PieSectorDataItem) {
  const fill = typeof props.fill === 'string' ? props.fill : '#71717a'
  return <Sector {...props} fill={fill} />
}

function renderLegendLabel(value: string) {
  return <span className="text-xs text-zinc-600 dark:text-zinc-400">{value}</span>
}

export function DeviceTypeChart() {
  const { data: assets = [], isLoading } = useAssets()

  const chartData = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const asset of assets) {
      const deviceClass = (asset as any).ai_analysis?.device_class ?? 'unknown'
      counts[deviceClass] = (counts[deviceClass] ?? 0) + 1
    }

    return Object.entries(counts)
      .map(([name, value]) => ({ name: name.replace('_', ' '), value, key: name, fill: COLORS[name] ?? '#71717a' }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8)
  }, [assets])

  return (
    <Card>
      <CardHeader>
        <CardTitle>Device Types</CardTitle>
        <span className="text-xs text-zinc-500">{assets.length} total</span>
      </CardHeader>
      <CardBody>
        {isLoading ? (
          <div className="h-48 flex items-center justify-center">
            <div className="w-32 h-32 rounded-full border-4 border-zinc-200 dark:border-zinc-800 border-t-sky-500 animate-spin" />
          </div>
        ) : chartData.length === 0 ? (
          <div className="h-48 flex items-center justify-center text-zinc-400 text-sm">
            No data — run a scan first
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                dataKey="value"
                nameKey="name"
                paddingAngle={2}
                activeShape={renderChartSector}
              />
              <Tooltip
                contentStyle={{
                  background: 'rgb(24 24 27)',
                  border: '1px solid rgb(39 39 42)',
                  borderRadius: '8px',
                  fontSize: '12px',
                  color: '#fff',
                }}
              />
              <Legend
                iconType="circle" iconSize={8}
                formatter={renderLegendLabel}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardBody>
    </Card>
  )
}
