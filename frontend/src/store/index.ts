import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { WsEvent, Asset } from '@/types'

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
  progress?: number
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
      store.addEvent({ id, timestamp, event: 'device_discovered', data: payload.data as Record<string, unknown> })
      if ('ip' in payload.data) store.addRecentlyDiscovered(payload.data.ip as string)
      break

    case 'scan_progress':
      store.addEvent({ id, timestamp, event: 'scan_progress', data: payload.data as Record<string, unknown> })
      store.setActiveScan({
        job_id: (payload.data as Record<string, unknown>).job_id as string,
        stage: (payload.data as Record<string, unknown>).stage as string,
        current_host: (payload.data as Record<string, unknown>).current_host as string,
        hosts_found: (payload.data as Record<string, unknown>).hosts_found as number,
      })
      break

    case 'scan_complete':
      store.addEvent({ id, timestamp, event: 'scan_complete', data: payload.data as Record<string, unknown> })
      store.setActiveScan(null)
      break

    case 'device_investigated':
      store.addEvent({ id, timestamp, event: 'device_investigated', data: payload.data as Record<string, unknown> })
      break

    case 'device_status_change':
      store.addEvent({ id, timestamp, event: 'device_status_change', data: payload.data as Record<string, unknown> })
      break

    default:
      store.addEvent({ id, timestamp, event: (payload as WsEvent).event, data: (payload as unknown as Record<string, unknown>) })
  }
}
