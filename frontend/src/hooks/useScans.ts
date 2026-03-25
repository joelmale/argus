import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scansApi } from '@/lib/api'
import type { ScanJob } from '@/types'

export function useScans() {
  return useQuery<ScanJob[]>({
    queryKey: ['scans'],
    queryFn: async () => {
      const { data } = await scansApi.list()
      return data
    },
    refetchInterval: 10_000,   // Poll more frequently — scan status changes fast
  })
}

export function useTriggerScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ targets, scan_type }: { targets?: string; scan_type: string }) =>
      scansApi.trigger(targets, scan_type),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}

export function useControlScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      action,
      mode,
      resume_in_minutes,
    }: {
      id: string
      action: 'cancel' | 'pause' | 'resume'
      mode?: 'discard' | 'preserve_discovery'
      resume_in_minutes?: number
    }) => scansApi.control(id, { action, mode, resume_in_minutes }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}

export function useQueueScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      action,
    }: {
      id: string
      action: 'move_up' | 'move_down' | 'move_to_front' | 'start_now'
    }) => scansApi.queue(id, { action }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}

export function useClearScanQueue() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => scansApi.clearQueue(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}
