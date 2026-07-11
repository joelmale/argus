import { useQuery } from '@tanstack/react-query'
import { systemApi } from '@/lib/api'
import { useAppStore } from '@/store'
import type { OperatorBrief } from '@/types'

export function useOperatorBrief(windowHours = 24) {
  const wsConnected = useAppStore((state) => state.wsConnected)
  return useQuery<OperatorBrief>({
    queryKey: ['operator-brief', windowHours],
    queryFn: async () => {
      const { data } = await systemApi.operatorBrief(windowHours)
      return data
    },
    refetchInterval: wsConnected ? false : 60_000,
  })
}
