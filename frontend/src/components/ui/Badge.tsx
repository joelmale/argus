import { cn } from '@/lib/utils'

/** Status badge: online / offline / unknown */
export function StatusBadge({ status }: { status: string }) {
  const cfg: Record<string, string> = {
    online:  'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30',
    offline: 'bg-red-500/15 text-red-600 dark:text-red-400 border border-red-500/30',
    unknown: 'bg-zinc-500/15 text-zinc-500 border border-zinc-500/30',
  }
  return (
    <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium', cfg[status] ?? cfg.unknown)}>
      <span className={cn('w-1.5 h-1.5 rounded-full',
        status === 'online' ? 'bg-emerald-500' : status === 'offline' ? 'bg-red-500' : 'bg-zinc-400'
      )} />
      {status}
    </span>
  )
}

/** Device class badge with colour per type */
const DEVICE_COLORS: Record<string, string> = {
  router:       'bg-sky-500/15 text-sky-600 dark:text-sky-400 border-sky-500/30',
  switch:       'bg-violet-500/15 text-violet-600 dark:text-violet-400 border-violet-500/30',
  access_point: 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border-cyan-500/30',
  firewall:     'bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30',
  server:       'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30',
  workstation:  'bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30',
  nas:          'bg-teal-500/15 text-teal-600 dark:text-teal-400 border-teal-500/30',
  printer:      'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30',
  ip_camera:    'bg-pink-500/15 text-pink-600 dark:text-pink-400 border-pink-500/30',
  smart_tv:     'bg-purple-500/15 text-purple-600 dark:text-purple-400 border-purple-500/30',
  iot_device:   'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30',
  voip:         'bg-lime-500/15 text-lime-600 dark:text-lime-400 border-lime-500/30',
  unknown:      'bg-zinc-500/15 text-zinc-500 dark:text-zinc-400 border-zinc-500/30',
}

export function DeviceClassBadge({ deviceClass }: { deviceClass: string | null | undefined }) {
  const cls = deviceClass || 'unknown'
  const label = cls.replace('_', ' ')
  return (
    <span className={cn('inline-flex px-2 py-0.5 rounded-full text-xs font-medium border',
      DEVICE_COLORS[cls] ?? DEVICE_COLORS.unknown)}>
      {label}
    </span>
  )
}

/** Confidence percentage pill */
export function ConfidenceBadge({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100)
  const color = pct >= 80 ? 'text-emerald-500' : pct >= 60 ? 'text-yellow-500' : 'text-orange-500'
  return (
    <span className={cn('text-xs font-mono tabular', color)}>{pct}%</span>
  )
}
