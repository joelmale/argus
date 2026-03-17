'use client'

import Link from 'next/link'
import { useState } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/Card'
import { useCurrentUser } from '@/hooks/useAuth'
import { useFindings, useIngestFindings, useUpdateFinding } from '@/hooks/useFindings'

export default function FindingsPage() {
  const { data: currentUser } = useCurrentUser()
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [importJson, setImportJson] = useState('')
  const { data: findings = [] } = useFindings({
    status: status || undefined,
    severity: severity || undefined,
  })
  const { mutate: ingest, isPending: isIngesting } = useIngestFindings()
  const { mutate: updateFinding, isPending: isUpdating } = useUpdateFinding()

  function handleImport() {
    const parsed = JSON.parse(importJson) as { source_tool?: string; findings?: Array<Record<string, unknown>> }
    ingest({ source_tool: parsed.source_tool || 'import', findings: parsed.findings || [] })
    setImportJson('')
  }

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto space-y-6">
        <div>
          <h2 className="text-xl font-bold text-zinc-900 dark:text-white">Findings</h2>
          <p className="text-sm text-zinc-500 mt-0.5">Imported assessment results correlated to assets and services.</p>
        </div>

        {currentUser?.role === 'admin' && (
          <Card>
            <CardHeader><CardTitle>Import Findings</CardTitle></CardHeader>
            <CardBody className="space-y-3">
              <p className="text-sm text-zinc-500">Paste JSON like <code className="font-mono">{"{\"source_tool\":\"nessus\",\"findings\":[...]}"}</code> to ingest imported assessment results.</p>
              <textarea value={importJson} onChange={(event) => setImportJson(event.target.value)} rows={8} className="w-full px-3 py-2 rounded-lg text-sm font-mono bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700" />
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
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded-full text-xs bg-red-500/10 text-red-600 dark:text-red-400">{finding.severity}</span>
                    <span className="px-2 py-0.5 rounded-full text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300">{finding.status}</span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-3 items-center">
                  <Link href={`/assets/${finding.asset_id}`} className="text-sm text-sky-500 hover:text-sky-600">
                    View affected asset
                  </Link>
                  {currentUser?.role === 'admin' && (
                    <>
                      <button onClick={() => updateFinding({ id: finding.id, status: 'resolved' })} disabled={isUpdating} className="text-sm text-emerald-600 hover:text-emerald-700">
                        Mark resolved
                      </button>
                      <button onClick={() => updateFinding({ id: finding.id, status: 'ignored' })} disabled={isUpdating} className="text-sm text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-200">
                        Ignore
                      </button>
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
