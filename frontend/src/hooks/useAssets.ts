import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { assetsApi, topologyApi } from '@/lib/api'
import type { Asset, ConfigBackupSnapshot, ConfigBackupTarget, Finding, TopologyGraph, WirelessAssociation } from '@/types'

const DAY_MS = 86_400_000
const INITIAL_RENDER_TIME = Date.now()

export function useAssets(params?: { search?: string; status?: string; tag?: string }) {
  return useQuery<Asset[]>({
    queryKey: ['assets', params],
    queryFn: async () => {
      const { data } = await assetsApi.list(params)
      return data
    },
    refetchInterval: 60_000,  // Background refresh every minute
  })
}

export function useAsset(id: string) {
  return useQuery<Asset>({
    queryKey: ['assets', id],
    queryFn: async () => {
      const { data } = await assetsApi.get(id)
      return data
    },
    enabled: !!id,
  })
}

export function useUpdateAsset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      assetsApi.update(id, payload),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: ['assets', id] })
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}

export function useAddAssetTag() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, tag }: { id: string; tag: string }) => assetsApi.addTag(id, tag),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: ['assets', id] })
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}

export function useRemoveAssetTag() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, tag }: { id: string; tag: string }) => assetsApi.removeTag(id, tag),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: ['assets', id] })
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}

export function useTopologyGraph() {
  return useQuery<TopologyGraph>({
    queryKey: ['topology'],
    queryFn: async () => {
      const { data } = await topologyApi.getGraph()
      return data
    },
    refetchInterval: 120_000,
  })
}

export function useConfigBackupTarget(id: string, enabled = true) {
  return useQuery<ConfigBackupTarget | null>({
    queryKey: ['assets', id, 'config-backup-target'],
    queryFn: async () => {
      const { data } = await assetsApi.getConfigBackupTarget(id)
      return data
    },
    enabled: enabled && !!id,
  })
}

export function useConfigBackups(id: string, enabled = true) {
  return useQuery<ConfigBackupSnapshot[]>({
    queryKey: ['assets', id, 'config-backups'],
    queryFn: async () => {
      const { data } = await assetsApi.listConfigBackups(id)
      return data
    },
    enabled: enabled && !!id,
    refetchInterval: 60_000,
  })
}

export function useUpsertConfigBackupTarget() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      payload,
    }: {
      id: string
      payload: Omit<ConfigBackupTarget, "id" | "asset_id" | "created_at" | "updated_at">
    }) => assetsApi.upsertConfigBackupTarget(id, payload),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: ['assets', id, 'config-backup-target'] })
      qc.invalidateQueries({ queryKey: ['assets', id, 'config-backups'] })
    },
  })
}

export function useTriggerConfigBackup() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => assetsApi.triggerConfigBackup(id),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ['assets', id, 'config-backups'] })
      qc.invalidateQueries({ queryKey: ['assets', id, 'config-backup-target'] })
    },
  })
}

export function useDownloadConfigBackup() {
  return useMutation({
    mutationFn: async ({ id, snapshotId }: { id: string; snapshotId: number }) => {
      const { data } = await assetsApi.downloadConfigBackup(id, snapshotId)
      return data as Blob
    },
  })
}

export function useDiffConfigBackup() {
  return useMutation({
    mutationFn: async ({ id, snapshotId, compareTo }: { id: string; snapshotId: number; compareTo?: number }) => {
      const { data } = await assetsApi.diffConfigBackup(id, snapshotId, compareTo)
      return data as string
    },
  })
}

export function useRestoreAssist() {
  return useMutation({
    mutationFn: async ({ id, snapshotId }: { id: string; snapshotId: number }) => {
      const { data } = await assetsApi.getRestoreAssist(id, snapshotId)
      return data as { driver: string; snapshot_id: number; host: string; warnings: string[]; commands: string[] }
    },
  })
}

export function useWirelessClients(id: string, enabled = true) {
  return useQuery<WirelessAssociation[]>({
    queryKey: ['assets', id, 'wireless-clients'],
    queryFn: async () => {
      const { data } = await assetsApi.listWirelessClients(id)
      return data
    },
    enabled: enabled && !!id,
    refetchInterval: 60_000,
  })
}

export function useAssetFindings(id: string, enabled = true) {
  return useQuery<Finding[]>({
    queryKey: ['assets', id, 'findings'],
    queryFn: async () => {
      const { data } = await assetsApi.listFindings(id)
      return data
    },
    enabled: enabled && !!id,
    refetchInterval: 60_000,
  })
}

/** Quick stats derived from the asset list — avoids a separate API call */
export function useAssetStats() {
  const { data: assets = [], isLoading } = useAssets()
  const online  = assets.filter((a) => a.status === 'online').length
  const offline = assets.filter((a) => a.status === 'offline').length
  const newToday = assets.filter((a) => {
    try { return INITIAL_RENDER_TIME - new Date(a.first_seen).getTime() < DAY_MS }
    catch { return false }
  }).length

  return { total: assets.length, online, offline, newToday, isLoading }
}
