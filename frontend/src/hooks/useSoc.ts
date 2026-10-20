'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { socApi } from '@/lib/api'

export interface SocAction {
  id: string
  agent?: string
  action: string
  target: string
  reason?: string
}

export interface SocIncidentRow {
  id: string
  created: string | null
  trigger: { type?: string; detail?: string | null; source?: string } | null
  status: string
  severity: string | null
  alert_severity: string | null
  cost_usd: number | null
  duration_s: number | null
}

export interface SocFindingState {
  key: string | null
  severity: string
  title: string
  agent?: string
  state: string
  occurrences?: number
}

export interface SocIncident {
  id: string
  status: string
  severity: string | null
  alert_severity: string | null
  trigger: SocIncidentRow['trigger']
  created: string | null
  report: string | null
  finding_states: SocFindingState[]
  resolved_findings: { key: string; title: string; agent: string }[]
  pending_approval: { question?: string; actions: SocAction[] } | null
  action_results: { action?: string; target?: string; decision?: string; result?: string }[]
  usage: { cost_usd?: number; duration_s?: number } | null
  error: string | null
}

export function useSocStatus() {
  return useQuery<{ configured: boolean; reachable: boolean }>({
    queryKey: ['soc', 'status'],
    queryFn: async () => (await socApi.status()).data,
    refetchInterval: 60_000,
  })
}

export function useSocIncidents(enabled = true) {
  return useQuery<SocIncidentRow[]>({
    queryKey: ['soc', 'incidents'],
    queryFn: async () => (await socApi.incidents(50)).data,
    enabled,
    refetchInterval: 15_000,
    retry: false,
  })
}

export function useSocIncident(id: string | null) {
  return useQuery<SocIncident>({
    queryKey: ['soc', 'incident', id],
    queryFn: async () => (await socApi.incident(id as string)).data,
    enabled: !!id,
    // Poll while InSOC is still working on it.
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 3_000 : 15_000),
    retry: false,
  })
}

export function useResumeIncident() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, approve, deny }: { id: string; approve: string[]; deny: string[] }) =>
      socApi.resume(id, { approve, deny }),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: ['soc', 'incident', variables.id] })
      qc.invalidateQueries({ queryKey: ['soc', 'incidents'] })
    },
  })
}
