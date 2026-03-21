import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { WsEvent } from '@/types'

export interface LiveEvent {
  id: string
  timestamp: string
  event: string
  data: Record<string, unknown>
}

export interface ActiveScan {
  job_id: string
  stage?: string
  current_host?: string
  hosts_found?: number
  hosts_port_scanned?: number
  hosts_fingerprinted?: number
  hosts_deep_probed?: number
  hosts_investigated?: number
  assets_created?: number
  assets_updated?: number
  progress?: number
  message?: string
}

interface AppState {
  // Layout
  sidebarCollapsed: boolean
  toggleSidebar: () => void

  // WebSocket connection status
  wsConnected: boolean
  setWsConnected: (v: boolean) => void

  // Live events feed (capped at 100)
  events: LiveEvent[]
  addEvent: (event: LiveEvent) => void
  clearEvents: () => void

  // Active scan state (if any scan is in progress)
  activeScan: ActiveScan | null
  setActiveScan: (scan: ActiveScan | null) => void

  // Recently discovered assets (for dashboard flash)
  recentlyDiscovered: string[]  // IP addresses
  addRecentlyDiscovered: (ip: string) => void
}

let _eventCounter = 0

function toRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? value as Record<string, unknown> : {}
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

      wsConnected: false,
      setWsConnected: (v) => set({ wsConnected: v }),

      events: [],
      addEvent: (event) =>
        set((s) => ({
          events: [event, ...s.events].slice(0, 100),
        })),
      clearEvents: () => set({ events: [] }),

      activeScan: null,
      setActiveScan: (scan) => set({ activeScan: scan }),

      recentlyDiscovered: [],
      addRecentlyDiscovered: (ip) =>
        set((s) => ({
          recentlyDiscovered: [ip, ...s.recentlyDiscovered].slice(0, 20),
        })),
    }),
    {
      name: 'argus-ui',
      partialize: (s) => ({ sidebarCollapsed: s.sidebarCollapsed }),
    },
  ),
)

/** Process a raw WS message payload into store state updates */
export function processWsEvent(payload: WsEvent, store: ReturnType<typeof useAppStore.getState>) {
  const id = String(++_eventCounter)
  const timestamp = new Date().toISOString()

  switch (payload.event) {
    case 'heartbeat':
      return  // Don't surface heartbeats in the UI

    case 'device_discovered':
      store.addEvent({ id, timestamp, event: 'device_discovered', data: toRecord(payload.data) })
      if ('ip' in payload.data) store.addRecentlyDiscovered(payload.data.ip as string)
      break

    case 'device_updated':
      store.addEvent({ id, timestamp, event: 'device_updated', data: toRecord(payload.data) })
      break

    case 'scan_progress':
      store.addEvent({ id, timestamp, event: 'scan_progress', data: toRecord(payload.data) })
      store.setActiveScan({
        job_id: payload.data.job_id,
        stage: payload.data.stage,
        current_host: payload.data.current_host,
        hosts_found: payload.data.hosts_found,
        hosts_port_scanned: payload.data.hosts_port_scanned,
        hosts_fingerprinted: payload.data.hosts_fingerprinted,
        hosts_deep_probed: payload.data.hosts_deep_probed,
        hosts_investigated: payload.data.hosts_investigated,
        assets_created: payload.data.assets_created,
        assets_updated: payload.data.assets_updated,
        progress: payload.data.progress,
        message: payload.data.message,
      })
      break

    case 'scan_complete':
      store.addEvent({ id, timestamp, event: 'scan_complete', data: toRecord(payload.data) })
      store.setActiveScan(null)
      break

    case 'device_investigated':
      store.addEvent({ id, timestamp, event: 'device_investigated', data: toRecord(payload.data) })
      break

    case 'device_status_change':
      store.addEvent({ id, timestamp, event: 'device_status_change', data: toRecord(payload.data) })
      break
  }
}
