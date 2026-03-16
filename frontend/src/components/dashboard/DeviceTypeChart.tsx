'use client'

import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { useAssets } from '@/hooks/useAssets'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'

const COLORS: Record<string, string> = {
  router: '#0ea5e9', switch: '#8b5cf6', access_point: '#06b6d4',
  server: '#22c55e', workstation: '#3b82f6', nas: '#14b8a6',
  printer: '#eab308', ip_camera: '#ec4899', smart_tv: '#a855f7',
  iot_device: '#f59e0b', firewall: '#f97316', voip: '#84cc16', unknown: '#71717a',
}

export function DeviceTypeChart() {
  const { data: assets = [], isLoading } = useAssets()

  const counts: Record<string, number> = {}
  for (const a of assets) {
    const cls = (a as any).ai_analysis?.device_class ?? 'unknown'
    counts[cls] = (counts[cls] ?? 0) + 1
  }

  const chartData = Object.entries(counts)
    .map(([name, value]) => ({ name: name.replace('_', ' '), value, key: name }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 8)

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
              <Pie data={chartData} cx="50%" cy="50%" innerRadius={50} outerRadius={80}
                dataKey="value" nameKey="name" paddingAngle={2}>
                {chartData.map((d) => (
                  <Cell key={d.key} fill={COLORS[d.key] ?? '#71717a'} />
                ))}
              </Pie>
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
                formatter={(v) => <span className="text-xs text-zinc-600 dark:text-zinc-400">{v}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardBody>
    </Card>
  )
}
