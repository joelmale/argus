'use client'

import { useSyncExternalStore } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { authApi, TOKEN_STORAGE_KEY } from '@/lib/api'
import type { AlertRule, ApiKey, AuditLogEntry, BackupDriver, ConfigBackupPolicy, CurrentUser, FingerprintDataset, HomeAssistantExport, IntegrationEvent, PluginInfo, ScannerConfig, TplinkDecoConfig, TplinkDecoSyncRun, UserRole } from '@/types'

const AUTH_EVENT = 'argus-auth-changed'

function hasBrowserWindow() {
  return typeof globalThis.window !== 'undefined'
}

function emitAuthChange() {
  if (hasBrowserWindow()) {
    globalThis.dispatchEvent(new Event(AUTH_EVENT))
  }
}

function getStoredToken() {
  if (!hasBrowserWindow()) {
    return null
  }
  return globalThis.localStorage.getItem(TOKEN_STORAGE_KEY)
}

export function setAuthToken(token: string) {
  if (!hasBrowserWindow()) {
    return
  }
  globalThis.localStorage.setItem(TOKEN_STORAGE_KEY, token)
  emitAuthChange()
}

export function clearAuthToken() {
  if (!hasBrowserWindow()) {
    return
  }
  globalThis.localStorage.removeItem(TOKEN_STORAGE_KEY)
  emitAuthChange()
}

export function useAuthToken() {
  return useSyncExternalStore(
    (onStoreChange) => {
      globalThis.addEventListener(AUTH_EVENT, onStoreChange)
      globalThis.addEventListener('storage', onStoreChange)
      return () => {
        globalThis.removeEventListener(AUTH_EVENT, onStoreChange)
        globalThis.removeEventListener('storage', onStoreChange)
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

export function useSetupStatus() {
  return useQuery<{ needs_setup: boolean; user_count: number }>({
    queryKey: ['auth', 'setup-status'],
    queryFn: async () => {
      const { data } = await authApi.getSetupStatus()
      return data
    },
    retry: false,
    staleTime: 5_000,
  })
}

export function useInitializeFirstAdmin() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: { username: string; password: string; email?: string }) => {
      const { data } = await authApi.initializeFirstAdmin(payload)
      return data as { access_token: string; token_type: string; user: CurrentUser }
    },
    onSuccess: async (data) => {
      setAuthToken(data.access_token)
      await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'setup-status'] })
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

export function useIntegrationEvents(enabled = true) {
  return useQuery<IntegrationEvent[]>({
    queryKey: ['system', 'integration-events'],
    queryFn: async () => {
      const { data } = await authApi.listIntegrationEvents()
      return data
    },
    enabled,
  })
}

export function useFingerprintDatasets(enabled = true) {
  return useQuery<FingerprintDataset[]>({
    queryKey: ['system', 'fingerprint-datasets'],
    queryFn: async () => {
      const { data } = await authApi.listFingerprintDatasets()
      return data
    },
    enabled,
  })
}

export function useHomeAssistantEntities(enabled = true) {
  return useQuery<HomeAssistantExport>({
    queryKey: ['system', 'home-assistant-entities'],
    queryFn: async () => {
      const { data } = await authApi.getHomeAssistantEntities()
      return data
    },
    enabled,
  })
}

export function useBackupPolicy(enabled = true) {
  return useQuery<ConfigBackupPolicy>({
    queryKey: ['system', 'backup-policy'],
    queryFn: async () => {
      const { data } = await authApi.getBackupPolicy()
      return data
    },
    enabled,
  })
}

export function useScannerConfig(enabled = true) {
  return useQuery<ScannerConfig>({
    queryKey: ['system', 'scanner-config'],
    queryFn: async () => {
      const { data } = await authApi.getScannerConfig()
      return data
    },
    enabled,
  })
}

export function useTplinkDecoModule(enabled = true) {
  return useQuery<{ config: TplinkDecoConfig; recent_runs: TplinkDecoSyncRun[] }>({
    queryKey: ['system', 'tplink-deco-module'],
    queryFn: async () => {
      const { data } = await authApi.getTplinkDecoModule()
      return data
    },
    enabled,
  })
}

export function useUpdateBackupPolicy() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: Omit<ConfigBackupPolicy, "id" | "last_run_at" | "created_at" | "updated_at">) => {
      const { data } = await authApi.updateBackupPolicy(payload)
      return data as ConfigBackupPolicy
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['system', 'backup-policy'] })
    },
  })
}

export function useUpdateScannerConfig() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: Omit<ScannerConfig, 'id' | 'detected_targets' | 'effective_targets' | 'last_scheduled_scan_at' | 'created_at' | 'updated_at'>) => {
      const { data } = await authApi.updateScannerConfig(payload)
      return data as ScannerConfig
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['system', 'scanner-config'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'audit-logs'] })
    },
  })
}

export function useUpdateTplinkDecoModule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: Omit<TplinkDecoConfig, 'id' | 'effective_owner_username' | 'last_tested_at' | 'last_sync_at' | 'last_status' | 'last_error' | 'last_client_count' | 'created_at' | 'updated_at'>) => {
      const { data } = await authApi.updateTplinkDecoModule(payload)
      return data as TplinkDecoConfig
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['system', 'tplink-deco-module'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'audit-logs'] })
    },
  })
}

export function useTestTplinkDecoModule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async () => {
      const { data } = await authApi.testTplinkDecoModule()
      return data as { status: string; client_count: number; base_url: string }
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['system', 'tplink-deco-module'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'audit-logs'] })
    },
  })
}

export function useSyncTplinkDecoModule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async () => {
      const { data } = await authApi.syncTplinkDecoModule()
      return data as { status: string; client_count: number; ingested_assets: number; log_excerpt_present: boolean; run_id: number }
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['system', 'tplink-deco-module'] })
      await queryClient.invalidateQueries({ queryKey: ['assets'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'audit-logs'] })
    },
  })
}

export function useRefreshFingerprintDataset() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (key: string) => {
      const { data } = await authApi.refreshFingerprintDataset(key)
      return data as FingerprintDataset
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['system', 'fingerprint-datasets'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'audit-logs'] })
    },
  })
}

export function useResetInventory() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (payload: { confirm: string; include_scan_history: boolean }) => {
      const { data } = await authApi.resetInventory(payload)
      return data as { assets_deleted: number; scans_deleted: number }
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['assets'] })
      await queryClient.invalidateQueries({ queryKey: ['scans'] })
      await queryClient.invalidateQueries({ queryKey: ['topology'] })
      await queryClient.invalidateQueries({ queryKey: ['findings'] })
      await queryClient.invalidateQueries({ queryKey: ['auth', 'audit-logs'] })
      await queryClient.invalidateQueries({ queryKey: ['system', 'home-assistant-entities'] })
    },
  })
}
