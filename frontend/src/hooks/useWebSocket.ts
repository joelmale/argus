'use client'

import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAppStore, processWsEvent } from '@/store'
import type { WsEvent } from '@/types'

const RECONNECT_DELAY_MS = 3000
const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? 'ws://localhost:8000'

export function useWebSocket(enabled = true) {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<NodeJS.Timeout | null>(null)
  const mountedRef = useRef(true)
  const queryClient = useQueryClient()

  const { setWsConnected } = useAppStore()

  function connect() {
    if (!enabled) return
    if (!mountedRef.current) return
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    const token = typeof window === 'undefined' ? null : localStorage.getItem('argus_token')
    if (!token) return

    const ws = new WebSocket(`${WS_URL}/ws/events?token=${encodeURIComponent(token)}`)
    wsRef.current = ws

    ws.onopen = () => {
      if (!mountedRef.current) return
      setWsConnected(true)
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
    }

    ws.onmessage = (e: MessageEvent) => {
      if (!mountedRef.current) return
      try {
        const payload = JSON.parse(e.data) as WsEvent
        const store = useAppStore.getState()
        processWsEvent(payload, store)

        // Invalidate relevant queries so TanStack Query refetches
        if (payload.event === 'device_discovered' || payload.event === 'device_updated' || payload.event === 'scan_complete') {
          queryClient.invalidateQueries({ queryKey: ['assets'] })
          queryClient.invalidateQueries({ queryKey: ['stats'] })
        }
        if (payload.event === 'scan_complete' || payload.event === 'scan_progress') {
          queryClient.invalidateQueries({ queryKey: ['scans'] })
        }
      } catch {
        // Ignore malformed messages
      }
    }

    ws.onclose = () => {
      if (!mountedRef.current) return
      setWsConnected(false)
      wsRef.current = null
      // Auto-reconnect after delay
      reconnectTimer.current = setTimeout(connect, RECONNECT_DELAY_MS)
    }

    ws.onerror = () => {
      ws.close()  // Triggers onclose → reconnect
    }
  }

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [enabled]) // eslint-disable-line react-hooks/exhaustive-deps
}
