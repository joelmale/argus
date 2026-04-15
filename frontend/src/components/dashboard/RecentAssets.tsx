'use client'

import Link from 'next/link'
import { useDashboardAssets } from '@/hooks/useAssets'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { StatusBadge, DeviceClassBadge } from '@/components/ui/Badge'
import { timeAgo } from '@/lib/utils'
import { ArrowRight } from 'lucide-react'

const SKELETON_ROW_KEYS = [
  'recent-asset-skeleton-1',
  'recent-asset-skeleton-2',
  'recent-asset-skeleton-3',
  'recent-asset-skeleton-4',
  'recent-asset-skeleton-5',
]

export function RecentAssets() {
  const { data: assets = [], isLoading } = useDashboardAssets()

  // Sort by first_seen desc, take 8
  const recent = [...assets]
    .sort((a, b) => new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime())
    .slice(0, 8)

  function renderContent() {
    if (isLoading) {
      return (
        <div className="divide-y divide-gray-100 dark:divide-zinc-800">
          {new Array(SKELETON_ROW_KEYS.length).fill(null).map((_, index) => (
            <div key={SKELETON_ROW_KEYS[index]} className="flex items-center gap-3 px-5 py-3">
              <div className="w-32 h-3.5 bg-zinc-200 dark:bg-zinc-800 rounded animate-pulse" />
              <div className="w-20 h-3.5 bg-zinc-200 dark:bg-zinc-800 rounded animate-pulse" />
            </div>
          ))}
        </div>
      )
    }

    if (recent.length === 0) {
      return (
        <div className="px-5 py-10 text-center text-zinc-400 text-sm">
          No assets yet — trigger a scan to discover your network
        </div>
      )
    }

    return (
      <div className="divide-y divide-gray-100 dark:divide-zinc-800">
        {recent.map((a) => (
          <Link
            key={a.id}
            href={`/assets/${a.id}`}
            className="flex items-center gap-3 px-5 py-3 hover:bg-gray-50 dark:hover:bg-zinc-800/50 transition-colors group"
          >
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-zinc-900 dark:text-white truncate group-hover:text-sky-500 transition-colors">
                {a.hostname || a.ip_address}
              </p>
              <p className="text-xs text-zinc-500 font-mono">{a.ip_address}</p>
            </div>
            <DeviceClassBadge deviceClass={a.ai_analysis?.device_class ?? a.device_type} />
            <StatusBadge status={a.status} />
            <span className="text-xs text-zinc-400 hidden sm:block">{timeAgo(a.first_seen)}</span>
          </Link>
        ))}
      </div>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recently Discovered</CardTitle>
        <Link href="/assets" className="text-xs text-sky-500 hover:text-sky-600 flex items-center gap-1">
          View all <ArrowRight className="w-3 h-3" />
        </Link>
      </CardHeader>
      <CardBody className="p-0">{renderContent()}</CardBody>
    </Card>
  )
}
