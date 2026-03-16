import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { formatDistanceToNow, format } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function timeAgo(date: string | Date): string {
  try {
    return formatDistanceToNow(new Date(date), { addSuffix: true })
  } catch {
    return 'unknown'
  }
}

export function formatDate(date: string | Date): string {
  try {
    return format(new Date(date), 'MMM d, yyyy HH:mm')
  } catch {
    return '—'
  }
}

export function shortId(id: string): string {
  return id.slice(0, 8)
}

/** Confidence → readable label + color */
export function confidenceLabel(conf: number): { label: string; color: string } {
  if (conf >= 0.9) return { label: 'High', color: 'text-emerald-500' }
  if (conf >= 0.7) return { label: 'Medium', color: 'text-yellow-500' }
  if (conf >= 0.4) return { label: 'Low', color: 'text-orange-500' }
  return { label: 'Unknown', color: 'text-zinc-500' }
}

/** Severity → Tailwind badge classes */
export function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'high':     return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    case 'medium':   return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    case 'low':      return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
    default:         return 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30'
  }
}
