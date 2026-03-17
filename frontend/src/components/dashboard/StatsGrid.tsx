'use client'

import { Server, Wifi, WifiOff, Sparkles } from 'lucide-react'
import { useAssetStats } from '@/hooks/useAssets'
import { useScans } from '@/hooks/useScans'

const DAY_MS = 86_400_000
const INITIAL_RENDER_TIME = Date.now()

/*
 * Tailwind v4 scans source files for static class strings.
 * Dynamic string construction (color.replace(...)) breaks detection,
 * so we use an explicit lookup for both the text colour and the icon bg.
 */
interface StatColors {
  text: string
  bg:   string
}

const STAT_COLORS: Record<string, StatColors> = {
  sky:    { text: 'text-sky-500',     bg: 'bg-sky-500/15'     },
  emerald:{ text: 'text-emerald-500', bg: 'bg-emerald-500/15' },
  red:    { text: 'text-red-500',     bg: 'bg-red-500/15'     },
  violet: { text: 'text-violet-500',  bg: 'bg-violet-500/15'  },
}

interface StatCardProps {
  icon:    React.ElementType
  label:   string
  value:   number | string
  sub?:    string
  color?:  keyof typeof STAT_COLORS
  loading?: boolean
}

function StatCard({ icon: Icon, label, value, sub, color = 'sky', loading }: StatCardProps) {
  const { text, bg } = STAT_COLORS[color]
  return (
    <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 flex items-start gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${bg}`}>
        <Icon className={`w-5 h-5 ${text}`} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">{label}</p>
        {loading
          ? <div className="h-7 w-16 bg-zinc-200 dark:bg-zinc-800 rounded animate-pulse" />
          : <p className="text-2xl font-bold tabular text-zinc-900 dark:text-white">{value}</p>
        }
        {sub && <p className="text-xs text-zinc-400 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

export function StatsGrid() {
  const { total, online, offline, newToday, isLoading } = useAssetStats()
  const { data: scans = [] } = useScans()

  const todayScans = scans.filter(s => {
    try { return INITIAL_RENDER_TIME - new Date(s.created_at).getTime() < DAY_MS }
    catch { return false }
  }).length

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard icon={Server}   label="Total Assets"  value={total}    color="sky"     loading={isLoading} />
      <StatCard icon={Wifi}     label="Online"        value={online}   color="emerald" loading={isLoading}
        sub={total > 0 ? `${Math.round(online / total * 100)}% of fleet` : undefined} />
      <StatCard icon={WifiOff}  label="Offline"       value={offline}  color="red"     loading={isLoading} />
      <StatCard icon={Sparkles} label="New Today"     value={newToday} color="violet"  loading={isLoading}
        sub={todayScans > 0 ? `${todayScans} scans today` : undefined} />
    </div>
  )
}
