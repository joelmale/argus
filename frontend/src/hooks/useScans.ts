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
    mutationFn: ({ targets, scan_type }: { targets: string; scan_type: string }) =>
      scansApi.trigger(targets, scan_type),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}
