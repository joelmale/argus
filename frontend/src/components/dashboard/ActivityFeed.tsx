'use client'

import { useAppStore, type LiveEvent } from '@/store'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { timeAgo } from '@/lib/utils'
import { Trash2 } from 'lucide-react'

const EVENT_LABELS: Record<string, { label: string; dot: string }> = {
  device_discovered:   { label: 'New device',        dot: 'bg-emerald-500' },
  device_investigated: { label: 'AI investigated',   dot: 'bg-sky-500' },
  scan_progress:       { label: 'Scan progress',     dot: 'bg-yellow-500' },
  scan_complete:       { label: 'Scan complete',     dot: 'bg-violet-500' },
  device_status_change:{ label: 'Status changed',    dot: 'bg-orange-500' },
  offline:             { label: 'Device offline',    dot: 'bg-red-500' },
}

function EventRow({ event }: { event: LiveEvent }) {
  const cfg = EVENT_LABELS[event.event] ?? { label: event.event, dot: 'bg-zinc-500' }

  // Build a human-readable summary
  const d = event.data
  let detail = ''
  if ('ip' in d)          detail = String(d.ip)
  if ('device_class' in d && detail) detail += ` — ${d.device_class}`
  if ('message' in d)     detail = String(d.message)
  if ('current_host' in d)detail = `Scanning ${d.current_host}`

  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-gray-100 dark:border-zinc-800 last:border-0">
      <span className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-zinc-900 dark:text-white">{cfg.label}</p>
        {detail && <p className="text-xs text-zinc-500 truncate">{detail}</p>}
      </div>
      <span className="text-xs text-zinc-400 flex-shrink-0">{timeAgo(event.timestamp)}</span>
    </div>
  )
}

export function ActivityFeed() {
  const { events, clearEvents } = useAppStore()

  return (
    <Card className="flex flex-col">
      <CardHeader>
        <CardTitle>Live Activity</CardTitle>
        <div className="flex items-center gap-2">
          {events.length > 0 && (
            <span className="text-xs text-zinc-500">{events.length} events</span>
          )}
          <button
            onClick={clearEvents}
            className="p-1 rounded text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 transition-colors"
            title="Clear events"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </CardHeader>
      <CardBody className="flex-1 overflow-y-auto max-h-80 p-0 px-5">
        {events.length === 0 ? (
          <div className="py-12 text-center text-zinc-400 text-sm">
            <p>No events yet.</p>
            <p className="text-xs mt-1">Events will appear here during scans.</p>
          </div>
        ) : (
          events.map((e) => <EventRow key={e.id} event={e} />)
        )}
      </CardBody>
    </Card>
  )
}
