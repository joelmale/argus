'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { findingsApi } from '@/lib/api'
import type { Finding } from '@/types'

export function useFindings(params?: { severity?: string; status?: string; asset_id?: string }) {
  return useQuery<Finding[]>({
    queryKey: ['findings', params],
    queryFn: async () => {
      const { data } = await findingsApi.list(params)
      return data
    },
    refetchInterval: 60_000,
  })
}

export function useFindingsSummary() {
  return useQuery<{ total: number; open: number; severity_counts: Record<string, number> }>({
    queryKey: ['findings', 'summary'],
    queryFn: async () => {
      const { data } = await findingsApi.summary()
      return data
    },
    refetchInterval: 60_000,
  })
}

export function useIngestFindings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (payload: { source_tool: string; findings: Array<Record<string, unknown>> }) => findingsApi.ingest(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}

export function useUpdateFinding() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) => findingsApi.update(id, { status }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
}
