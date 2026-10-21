'use client'

import Link from 'next/link'
import { useState } from 'react'
import { Loader2, ShieldCheck } from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/Card'
import { useCurrentUser } from '@/hooks/useAuth'
import { useResumeIncident, useSocDigest, useSocIncident, useSocIncidents, useSocStatus, type SocIncidentRow } from '@/hooks/useSoc'
import { cn, getErrorDetail } from '@/lib/utils'

// InSOC uses nominal/info/warning/critical.
function socSeverityColor(severity: string | null | undefined) {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-500 border-red-500/30'
    case 'warning':  return 'bg-yellow-500/20 text-yellow-600 dark:text-yellow-400 border-yellow-500/30'
    case 'info':     return 'bg-blue-500/20 text-blue-500 border-blue-500/30'
    default:         return 'bg-zinc-500/15 text-zinc-500 border-zinc-500/30'
  }
}

function statusLabel(status: string) {
  return status === 'awaiting_approval' ? 'needs approval' : status
}

function when(iso: string | null) {
  return iso ? new Date(iso).toLocaleString() : '—'
}

function triggerLabel(row: Pick<SocIncidentRow, 'trigger'>) {
  const t = row.trigger
  if (!t?.type) return 'incident'
  return t.source ? `${t.type} · ${t.source}` : t.type
}

function IncidentDetail({ id, isAdmin }: Readonly<{ id: string; isAdmin: boolean }>) {
  const { data: incident, isLoading, error } = useSocIncident(id)
  const { mutate: resume, isPending, error: resumeError } = useResumeIncident()
  const [decisions, setDecisions] = useState<Record<string, 'approve' | 'deny'>>({})

  if (isLoading) {
    return <p className="text-sm text-zinc-500 inline-flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Loading incident…</p>
  }
  if (error || !incident) {
    return <p className="text-sm text-red-500">{getErrorDetail(error) ?? 'Could not load this incident from InSOC.'}</p>
  }

  const actions = incident.pending_approval?.actions ?? []
  const decided = actions.filter((action) => decisions[action.id])

  function submit() {
    resume({
      id,
      approve: actions.filter((a) => decisions[a.id] === 'approve').map((a) => a.id),
      deny: actions.filter((a) => decisions[a.id] === 'deny').map((a) => a.id),
    }, { onSuccess: () => setDecisions({}) })
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm text-zinc-700 dark:text-zinc-200">{incident.id}</span>
        <span className={cn('px-2 py-0.5 rounded-full text-xs border capitalize', socSeverityColor(incident.severity))}>{incident.severity ?? 'nominal'}</span>
        <span className="px-2 py-0.5 rounded-full text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300">{statusLabel(incident.status)}</span>
        <span className="text-xs text-zinc-500">{triggerLabel(incident)} · {when(incident.created)}</span>
      </div>

      {incident.error && <p className="text-sm text-red-500">InSOC error: {incident.error}</p>}

      {actions.length > 0 && (
        <div className="rounded-xl border border-amber-300/60 bg-amber-50 dark:bg-amber-950/20 dark:border-amber-900 p-4 space-y-3">
          <p className="text-sm font-medium text-amber-800 dark:text-amber-200">
            {incident.pending_approval?.question ?? 'Approve the following remediation actions?'}
          </p>
          {actions.map((action) => (
            <div key={action.id} className="flex flex-col md:flex-row md:items-center gap-2 text-sm">
              <div className="flex-1">
                <span className="font-medium">{action.action.replaceAll('_', ' ')}</span> <span className="font-mono">{action.target}</span>
                {action.reason && <p className="text-xs text-zinc-500 mt-0.5">{action.reason}</p>}
              </div>
              {isAdmin ? (
                <div className="flex gap-2">
                  {(['approve', 'deny'] as const).map((choice) => (
                    <button
                      key={choice}
                      onClick={() => setDecisions((current) => ({ ...current, [action.id]: choice }))}
                      className={cn(
                        'px-3 py-1 rounded-lg text-xs border capitalize',
                        decisions[action.id] === choice
                          ? choice === 'approve' ? 'bg-emerald-500 text-white border-emerald-500' : 'bg-red-500 text-white border-red-500'
                          : 'border-zinc-300 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300',
                      )}
                    >
                      {choice}
                    </button>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-zinc-500">An admin must approve or deny this.</span>
              )}
            </div>
          ))}
          {isAdmin && (
            <div className="flex items-center gap-3">
              <button
                onClick={submit}
                disabled={isPending || decided.length === 0}
                className="px-4 py-2 rounded-lg text-sm bg-sky-500 text-white disabled:opacity-60"
              >
                {isPending ? 'Sending…' : `Submit ${decided.length} decision${decided.length === 1 ? '' : 's'}`}
              </button>
              {resumeError && <span className="text-sm text-red-500">{getErrorDetail(resumeError) ?? 'Could not send the decision.'}</span>}
            </div>
          )}
        </div>
      )}

      {incident.report && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-zinc-500 mb-1.5">Report</h4>
          {/* Model-written text: rendered as plain text, never as HTML. */}
          <div className="text-sm whitespace-pre-wrap text-zinc-700 dark:text-zinc-200 rounded-lg bg-gray-50 dark:bg-zinc-900 p-3">{incident.report}</div>
        </div>
      )}

      {incident.finding_states.length > 0 && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-zinc-500 mb-1.5">Findings in this run</h4>
          <ul className="space-y-1.5">
            {incident.finding_states.map((finding, index) => (
              <li key={`${finding.key ?? 'unkeyed'}-${index}`} className="text-sm flex flex-wrap items-center gap-2">
                <span className={cn('px-2 py-0.5 rounded-full text-[11px] border capitalize', socSeverityColor(finding.severity))}>{finding.severity}</span>
                <span className="px-2 py-0.5 rounded-full text-[11px] bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300">{finding.state}</span>
                <span className="text-zinc-700 dark:text-zinc-200">{finding.title}</span>
                {finding.key && <span className="font-mono text-[11px] text-zinc-500">{finding.key}</span>}
              </li>
            ))}
          </ul>
          <Link href="/findings" className="text-xs text-sky-500 hover:text-sky-600 mt-2 inline-block">Acknowledge or track these on the Findings page (source: InSOC)</Link>
        </div>
      )}

      {incident.resolved_findings.length > 0 && (
        <p className="text-xs text-zinc-500">Resolved this run: {incident.resolved_findings.map((f) => f.title).join(', ')}</p>
      )}

      {incident.action_results.length > 0 && (
        <div>
          <h4 className="text-xs uppercase tracking-wide text-zinc-500 mb-1.5">Actions</h4>
          <ul className="text-sm space-y-1">
            {incident.action_results.map((result, index) => (
              <li key={index}>{result.decision ?? 'done'}: {result.action} {result.target}{result.result ? ` (${result.result})` : ''}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function DailyDigest() {
  const { data: digest, isLoading, error } = useSocDigest()
  return (
    <Card>
      <CardHeader><CardTitle>Daily digest</CardTitle></CardHeader>
      <CardBody className="space-y-2">
        {isLoading && <p className="text-sm text-zinc-500">Loading…</p>}
        {error && <p className="text-sm text-red-500">{getErrorDetail(error) ?? 'Could not load the digest from InSOC.'}</p>}
        {digest && (
          <>
            <p className="text-xs text-zinc-500">
              {digest.open} open · {digest.acknowledged} acknowledged
              {digest.next_scheduled ? ` · next sent ${when(digest.next_scheduled)}` : ' · scheduled digest is off'}
            </p>
            {digest.text ? (
              // InSOC-built text: rendered as plain text, never as HTML.
              <div className="text-sm whitespace-pre-wrap text-zinc-700 dark:text-zinc-200 rounded-lg bg-gray-50 dark:bg-zinc-900 p-3">{digest.text}</div>
            ) : (
              <p className="text-sm text-zinc-500">No open findings. Nothing to report.</p>
            )}
          </>
        )}
      </CardBody>
    </Card>
  )
}

export default function SecurityPage() {
  const { data: currentUser } = useCurrentUser()
  const { data: status } = useSocStatus()
  const ready = status?.configured === true
  const { data: incidents = [], error, isLoading } = useSocIncidents(ready)
  const [selected, setSelected] = useState<string | null>(null)
  const active = selected ?? incidents[0]?.id ?? null
  const isAdmin = currentUser?.role === 'admin'

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-6">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Security</h2>
          <p className="text-sm text-zinc-500 mt-0.5">InSOC&apos;s daily digest, its investigations, and the actions waiting for your approval. Findings from these runs appear on the Findings page.</p>
        </div>

        {status && !status.configured && (
          <Card>
            <CardBody className="text-sm text-zinc-600 dark:text-zinc-300 space-y-1">
              <p className="font-medium inline-flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> InSOC isn&apos;t connected.</p>
              <p>Set <code className="font-mono">INSOC_URL</code> (e.g. <code className="font-mono">http://192.168.100.20:8765</code>) and <code className="font-mono">INSOC_API_TOKEN</code> on the Argus backend to show incidents here.</p>
            </CardBody>
          </Card>
        )}
        {status?.configured && !status.reachable && (
          <p className="text-sm text-amber-600">InSOC is configured but not answering right now.</p>
        )}

        {ready && <DailyDigest />}

        {ready && (
          <div className="grid grid-cols-1 lg:grid-cols-[360px_1fr] gap-6">
            <Card>
              <CardHeader><CardTitle>Incidents</CardTitle></CardHeader>
              <CardBody className="space-y-1.5">
                {isLoading && <p className="text-sm text-zinc-500">Loading…</p>}
                {error && <p className="text-sm text-red-500">{getErrorDetail(error) ?? 'Could not load incidents.'}</p>}
                {!isLoading && !error && incidents.length === 0 && <p className="text-sm text-zinc-500">No incidents yet.</p>}
                {incidents.map((row) => (
                  <button
                    key={row.id}
                    onClick={() => setSelected(row.id)}
                    className={cn(
                      'w-full text-left rounded-lg px-3 py-2 border transition',
                      row.id === active ? 'border-sky-400 bg-sky-50 dark:bg-sky-950/30' : 'border-transparent hover:bg-gray-50 dark:hover:bg-zinc-900',
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <span className={cn('px-1.5 py-0.5 rounded-full text-[10px] border capitalize', socSeverityColor(row.severity))}>{row.severity ?? 'nominal'}</span>
                      <span className={cn('text-xs', row.status === 'awaiting_approval' ? 'text-amber-600 font-medium' : 'text-zinc-500')}>{statusLabel(row.status)}</span>
                    </div>
                    <p className="text-sm text-zinc-800 dark:text-zinc-100 mt-1">{triggerLabel(row)}</p>
                    <p className="text-[11px] text-zinc-500">{when(row.created)}</p>
                  </button>
                ))}
              </CardBody>
            </Card>
            <Card>
              <CardHeader><CardTitle>Details</CardTitle></CardHeader>
              <CardBody>
                {active ? <IncidentDetail key={active} id={active} isAdmin={isAdmin} /> : <p className="text-sm text-zinc-500">Select an incident.</p>}
              </CardBody>
            </Card>
          </div>
        )}
      </div>
    </AppShell>
  )
}
