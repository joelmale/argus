'use client'

import { useSyncExternalStore } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { authApi, TOKEN_STORAGE_KEY } from '@/lib/api'
import type { AlertRule, ApiKey, AuditLogEntry, BackupDriver, CurrentUser, PluginInfo, UserRole } from '@/types'

const AUTH_EVENT = 'argus-auth-changed'

function emitAuthChange() {
  window.dispatchEvent(new Event(AUTH_EVENT))
}

function getStoredToken() {
  return typeof window === 'undefined' ? null : localStorage.getItem(TOKEN_STORAGE_KEY)
}

export function setAuthToken(token: string) {
  localStorage.setItem(TOKEN_STORAGE_KEY, token)
  emitAuthChange()
}

export function clearAuthToken() {
  localStorage.removeItem(TOKEN_STORAGE_KEY)
  emitAuthChange()
}

export function useAuthToken() {
  return useSyncExternalStore(
    (onStoreChange) => {
      window.addEventListener(AUTH_EVENT, onStoreChange)
      window.addEventListener('storage', onStoreChange)
      return () => {
        window.removeEventListener(AUTH_EVENT, onStoreChange)
        window.removeEventListener('storage', onStoreChange)
      }
    },
    getStoredToken,
    () => null,
  )
}

export function useCurrentUser() {
  const token = useAuthToken()

  return useQuery<CurrentUser>({
    queryKey: ['auth', 'me', token],
    queryFn: async () => {
      const { data } = await authApi.me()
      return data
    },
    enabled: !!token,
    retry: false,
  })
}

export function useLogin() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ username, password }: { username: string; password: string }) => {
      const { data } = await authApi.login(username, password)
      return data as { access_token: string; token_type: string }
    },
    onSuccess: async (data) => {
      setAuthToken(data.access_token)
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
    },
  })
}

export function useLogout() {
  const queryClient = useQueryClient()

  return () => {
    clearAuthToken()
    queryClient.removeQueries({ queryKey: ['auth'] })
  }
}

export function useUsers(enabled = true) {
  return useQuery<CurrentUser[]>({
    queryKey: ['auth', 'users'],
    queryFn: async () => {
      const { data } = await authApi.listUsers()
      return data
    },
    enabled,
  })
}

export function useCreateUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: { username: string; password: string; email?: string; role: UserRole }) => {
      const { data } = await authApi.createUser(payload)
      return data as CurrentUser
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['auth', 'users'] })
    },
  })
}

export function useUpdateUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ id, payload }: { id: string; payload: { role?: UserRole; is_active?: boolean } }) => {
      const { data } = await authApi.updateUser(id, payload)
      return data as CurrentUser
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['auth', 'users'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
    },
  })
}

export function useApiKeys(enabled = true) {
  return useQuery<ApiKey[]>({
    queryKey: ['auth', 'api-keys'],
    queryFn: async () => {
      const { data } = await authApi.listApiKeys()
      return data
    },
    enabled,
  })
}

export function useCreateApiKey() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: { name: string }) => {
      const { data } = await authApi.createApiKey(payload)
      return data as ApiKey & { token: string }
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['auth', 'api-keys'] })
    },
  })
}

export function useDeleteApiKey() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (id: string) => {
      await authApi.deleteApiKey(id)
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['auth', 'api-keys'] })
    },
  })
}

export function useAuditLogs(enabled = true) {
  return useQuery<AuditLogEntry[]>({
    queryKey: ['auth', 'audit-logs'],
    queryFn: async () => {
      const { data } = await authApi.listAuditLogs()
      return data
    },
    enabled,
    refetchInterval: 60_000,
  })
}

export function useAlertRules(enabled = true) {
  return useQuery<AlertRule[]>({
    queryKey: ['auth', 'alert-rules'],
    queryFn: async () => {
      const { data } = await authApi.listAlertRules()
      return data
    },
    enabled,
  })
}

export function useUpdateAlertRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({
      id,
      payload,
    }: {
      id: number
      payload: { enabled?: boolean; notify_email?: boolean; notify_webhook?: boolean }
    }) => {
      const { data } = await authApi.updateAlertRule(id, payload)
      return data as AlertRule
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['auth', 'alert-rules'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'audit-logs'] })
    },
  })
}

export function useBackupDrivers(enabled = true) {
  return useQuery<BackupDriver[]>({
    queryKey: ['system', 'backup-drivers'],
    queryFn: async () => {
      const { data } = await authApi.listBackupDrivers()
      return data
    },
    enabled,
  })
}

export function usePlugins(enabled = true) {
  return useQuery<PluginInfo[]>({
    queryKey: ['system', 'plugins'],
    queryFn: async () => {
      const { data } = await authApi.listPlugins()
      return data
    },
    enabled,
    refetchInterval: 60_000,
  })
}
