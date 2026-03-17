import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { assetsApi, topologyApi } from '@/lib/api'
import type { Asset, TopologyGraph } from '@/types'

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
