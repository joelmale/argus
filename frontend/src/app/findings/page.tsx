'use client'

import Link from 'next/link'
import { useState } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/Card'
import { useCurrentUser } from '@/hooks/useAuth'
import { useAckFinding, useFindings, useIngestFindings, useUnackFinding, useUpdateFinding } from '@/hooks/useFindings'
import { cn, severityColor } from '@/lib/utils'

export default function FindingsPage() {
  const { data: currentUser } = useCurrentUser()
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [importJson, setImportJson] = useState('')
  const [importError, setImportError] = useState<string | null>(null)
  const [importSuccessMessage, setImportSuccessMessage] = useState<string | null>(null)
  const { data: findings = [] } = useFindings({
    status: status || undefined,
    severity: severity || undefined,
    source_tool: source || undefined,
  })
  const { mutate: ingest, isPending: isIngesting } = useIngestFindings()
  const { mutate: updateFinding, isPending: isUpdating } = useUpdateFinding()
  const { mutate: ackFinding, isPending: isAcking } = useAckFinding()
  const { mutate: unackFinding, isPending: isUnacking } = useUnackFinding()
  const canTriage = currentUser?.role === 'admin' || currentUser?.role === 'service'
  const busy = isUpdating || isAcking || isUnacking

  function handleImport() {
    setImportError(null)
    setImportSuccessMessage(null)
    try {
      const parsed = JSON.parse(importJson) as { source_tool?: string; findings?: Array<Record<string, unknown>> }
      if (typeof parsed !== 'object' || parsed === null) {
        throw new Error('JSON input must be an object.')
      }
      ingest(
        { source_tool: parsed.source_tool || 'import', findings: parsed.findings || [] },
        {
          onSuccess: (response) => {
            const { created, updated, skipped } = response.data
            setImportSuccessMessage(
              `Imported findings: ${created} created, ${updated} updated, ${skipped} skipped.`
            )
            setImportJson('')
          },
          onError: (err: any) => {
            const detail = err.response?.data?.detail
            setImportError(typeof detail === 'string' ? detail : err.message || 'Server error during ingestion')
          },
        }
      )
    } catch (err: any) {
      setImportError(err.message || 'Invalid JSON format')
    }
  }

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-6">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Findings</h2>
          <p className="text-sm text-zinc-500 mt-0.5">Assessment results and InSOC findings, correlated to assets. Acknowledge a known issue to stop re-alerts until it resolves or gets worse.</p>
        </div>

        {currentUser?.role === 'admin' && (
          <Card>
            <CardHeader><CardTitle>Import Findings</CardTitle></CardHeader>
            <CardBody className="space-y-3">
              <p className="text-sm text-zinc-500">Paste JSON like <code className="font-mono">{"{\"source_tool\":\"nessus\",\"findings\":[...]}"}</code> to ingest imported assessment results.</p>
              <textarea
                value={importJson}
                onChange={(event) => {
                  setImportJson(event.target.value)
                  setImportError(null)
                  setImportSuccessMessage(null)
                }}
                rows={8}
                className="w-full px-3 py-2 rounded-lg text-sm font-mono bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
              />
              {importError && (
                <div className="text-sm text-red-600 dark:text-red-400 bg-red-500/10 px-3 py-2 rounded-lg border border-red-500/20">
                  {importError}
                </div>
              )}
              {importSuccessMessage && (
                <div className="text-sm text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 px-3 py-2 rounded-lg border border-emerald-500/20">
                  {importSuccessMessage}
                </div>
              )}
              <button onClick={handleImport} disabled={isIngesting || !importJson.trim()} className="px-4 py-2 rounded-lg text-sm bg-sky-500 text-white">
                {isIngesting ? 'Importing…' : 'Import findings'}
              </button>
            </CardBody>
          </Card>
        )}

        <div className="flex flex-wrap gap-3">
          <select value={severity} onChange={(event) => setSeverity(event.target.value)} className="px-3 py-2 rounded-lg text-sm bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select value={status} onChange={(event) => setStatus(event.target.value)} className="px-3 py-2 rounded-lg text-sm bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800">
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="ignored">Ignored</option>
          </select>
          <select value={source} onChange={(event) => setSource(event.target.value)} className="px-3 py-2 rounded-lg text-sm bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800">
            <option value="">All sources</option>
            <option value="insoc">InSOC</option>
            <option value="import">Import</option>
          </select>
        </div>

        <Card>
          <CardHeader><CardTitle>Assessment Findings</CardTitle></CardHeader>
          <CardBody className="space-y-3">
            {findings.length === 0 ? (
              <p className="text-sm text-zinc-500">No findings imported yet.</p>
            ) : findings.map((finding) => (
              <div key={finding.id} className="rounded-xl border border-gray-200 dark:border-zinc-800 p-4 space-y-3">
                <div className="flex flex-col md:flex-row md:items-center gap-3">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">{finding.title}</p>
                    <p className="text-xs text-zinc-500 mt-1">
                      {finding.source_tool} · {finding.cve || 'no CVE'} · {finding.service || 'service unknown'}
                      {finding.port_number ? ` · ${finding.port_number}/${finding.protocol || 'tcp'}` : ''}
                    </p>
                    {finding.description && <p className="text-sm text-zinc-600 dark:text-zinc-300 mt-2">{finding.description}</p>}
                    <p className="text-xs text-zinc-500 mt-1">
                      Seen {finding.occurrences}× · last {new Date(finding.last_seen).toLocaleString()}
                      {finding.state === 'acknowledged' && finding.ack_until && (
                        <>
                          {' · acknowledged'}
                          {finding.acked_by ? ` by ${finding.acked_by}` : ''}
                          {new Date(finding.ack_until).getFullYear() < new Date().getFullYear() + 5
                            ? ` until ${new Date(finding.ack_until).toLocaleString()}`
                            : ' until resolved'}
                          {finding.ack_note ? ` (${finding.ack_note})` : ''}
                        </>
                      )}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={cn("px-2 py-0.5 rounded-full text-xs border capitalize", severityColor(finding.severity))}>{finding.severity}</span>
                    <span className={cn(
                      "px-2 py-0.5 rounded-full text-xs",
                      finding.state === 'acknowledged'
                        ? 'bg-sky-500/15 text-sky-600 dark:text-sky-300'
                        : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300',
                    )}>{finding.state}</span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-3 items-center">
                  <Link href={`/assets/${finding.asset_id}`} className="text-sm text-sky-500 hover:text-sky-600">
                    View affected asset
                  </Link>
                  {canTriage && finding.state === 'open' && (
                    <>
                      <button onClick={() => ackFinding({ id: finding.id, hours: 24 })} disabled={busy} className="text-sm text-sky-600 hover:text-sky-700">
                        Ack 24h
                      </button>
                      <button onClick={() => ackFinding({ id: finding.id, hours: 24 * 7 })} disabled={busy} className="text-sm text-sky-600 hover:text-sky-700">
                        Ack 7d
                      </button>
                      <button onClick={() => ackFinding({ id: finding.id, hours: null })} disabled={busy} className="text-sm text-sky-600 hover:text-sky-700">
                        Ack until resolved
                      </button>
                    </>
                  )}
                  {canTriage && finding.state === 'acknowledged' && (
                    <button onClick={() => unackFinding(finding.id)} disabled={busy} className="text-sm text-sky-600 hover:text-sky-700">
                      Unacknowledge
                    </button>
                  )}
                  {currentUser?.role === 'admin' && (
                    <>
                      {finding.status !== 'resolved' && (
                        <button onClick={() => updateFinding({ id: finding.id, status: 'resolved' })} disabled={busy} className="text-sm text-emerald-600 hover:text-emerald-700">
                          Mark resolved
                        </button>
                      )}
                      {finding.status !== 'ignored' ? (
                        <button onClick={() => updateFinding({ id: finding.id, status: 'ignored' })} disabled={busy} className="text-sm text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-200">
                          Ignore
                        </button>
                      ) : (
                        <button onClick={() => updateFinding({ id: finding.id, status: 'open' })} disabled={busy} className="text-sm text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-200">
                          Stop ignoring
                        </button>
                      )}
                    </>
                  )}
                </div>
              </div>
            ))}
          </CardBody>
        </Card>
      </div>
    </AppShell>
  )
}
