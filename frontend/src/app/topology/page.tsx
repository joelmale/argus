'use client'

import dynamic from 'next/dynamic'
import { AppShell } from '@/components/layout/AppShell'

// Cytoscape must be loaded client-side only — no SSR
const TopologyMap = dynamic(
  () => import('@/components/topology/TopologyMap').then((m) => m.TopologyMap),
  {
    ssr: false,
    loading: () => (
      <div className="flex items-center justify-center h-full text-zinc-400 text-sm">
        Loading topology…
      </div>
    ),
  },
)

export default function TopologyPage() {
  return (
    <AppShell>
      <div className="flex flex-col h-[calc(100vh-4rem)]">
        <div className="flex-shrink-0 mb-3">
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Network Topology</h2>
          <p className="text-sm text-zinc-500 mt-0.5">
            Force-directed map of discovered devices. Click a node to view asset details.
          </p>
        </div>
        <div className="flex-1 min-h-0 rounded-xl border border-gray-200 dark:border-zinc-800 overflow-hidden">
          <TopologyMap />
        </div>
      </div>
    </AppShell>
  )
}
