import { AppShell } from '@/components/layout/AppShell'
import { StatsGrid } from '@/components/dashboard/StatsGrid'
import { ActivityFeed } from '@/components/dashboard/ActivityFeed'
import { DeviceTypeChart } from '@/components/dashboard/DeviceTypeChart'
import { FindingsSummary } from '@/components/dashboard/FindingsSummary'
import { RecentAssets } from '@/components/dashboard/RecentAssets'
import { QuickScan } from '@/components/scans/QuickScan'

export default function DashboardPage() {
  return (
    <AppShell>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Stats row */}
        <StatsGrid />

        {/* Middle row: chart + quick scan + activity */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <DeviceTypeChart />
          <QuickScan />
          <ActivityFeed />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <FindingsSummary />
          <RecentAssets />
        </div>
      </div>
    </AppShell>
  )
}
