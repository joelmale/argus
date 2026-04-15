'use client'

import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useAppStore, processWsEvent } from '@/store'
import { TOKEN_STORAGE_KEY } from '@/lib/api'
import type { WsEvent } from '@/types'

function getWsBaseUrl() {
  if (process.env.NEXT_PUBLIC_WS_URL) {
    return process.env.NEXT_PUBLIC_WS_URL
  }
  if (typeof globalThis.window === 'object') {
    return globalThis.location.origin.replace(/^http/i, 'ws')
  }
  return ''
}

function getStoredToken() {
  if (globalThis.window === undefined) {
    return null
  }
  return globalThis.localStorage.getItem(TOKEN_STORAGE_KEY)
}

export function useWebSocket(enabled = true) {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttempt = useRef(0)
  const mountedRef = useRef(true)
  const queryClient = useQueryClient()

  const { setWsConnected, setWsReconnecting } = useAppStore()

  function clearReconnectTimer() {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current)
      reconnectTimer.current = null
    }
  }

  function scheduleReconnect() {
    clearReconnectTimer()
    setWsReconnecting(true)
    const delayMs = Math.min(1000 * 2 ** reconnectAttempt.current, 30_000)
    reconnectAttempt.current += 1
    reconnectTimer.current = setTimeout(connect, delayMs)
  }

  function connect() {
    if (!enabled) return
    if (!mountedRef.current) return
    if (wsRef.current?.readyState === WebSocket.OPEN || wsRef.current?.readyState === WebSocket.CONNECTING) return

    const token = getStoredToken()
    if (!token) {
      setWsConnected(false)
      setWsReconnecting(false)
      return
    }

    const ws = new WebSocket(`${getWsBaseUrl()}/ws/events`)
    wsRef.current = ws

    ws.onopen = () => {
      if (!mountedRef.current) return
      ws.send(JSON.stringify({ type: 'auth', token }))
      reconnectAttempt.current = 0
      setWsConnected(true)
      setWsReconnecting(false)
      clearReconnectTimer()
    }

    ws.onmessage = (e: MessageEvent) => {
      if (!mountedRef.current) return
      try {
        const payload = JSON.parse(e.data) as WsEvent
        const store = useAppStore.getState()
        processWsEvent(payload, store)

        // Invalidate relevant queries so TanStack Query refetches
        if (payload.event === 'device_discovered' || payload.event === 'device_updated' || payload.event === 'device_status_change' || payload.event === 'scan_complete') {
          queryClient.invalidateQueries({ queryKey: ['assets'] })
          queryClient.invalidateQueries({ queryKey: ['asset-stats'] })
        }
        if (payload.event === 'scan_complete' || payload.event === 'scan_progress') {
          queryClient.invalidateQueries({ queryKey: ['scans'] })
        }
        if (payload.event === 'topology:updated' || payload.event === 'scan_complete') {
          queryClient.invalidateQueries({ queryKey: ['topology'] })
        }
      } catch {
        // Ignore malformed messages
      }
    }

    ws.onclose = () => {
      if (!mountedRef.current) return
      setWsConnected(false)
      wsRef.current = null
      if (!enabled || !getStoredToken()) {
        setWsReconnecting(false)
        return
      }
      scheduleReconnect()
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
      clearReconnectTimer()
      setWsReconnecting(false)
      wsRef.current?.close()
    }
  }, [enabled]) // eslint-disable-line react-hooks/exhaustive-deps
}
