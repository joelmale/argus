'use client'

import { useState } from 'react'
import { AppShell } from '@/components/layout/AppShell'
import { useCurrentUser } from '@/hooks/useAuth'
import { useAddAssetTag, useAsset, useRemoveAssetTag, useUpdateAsset } from '@/hooks/useAssets'
import { StatusBadge, DeviceClassBadge, ConfidenceBadge } from '@/components/ui/Badge'
import { Card, CardHeader, CardTitle, CardBody } from '@/components/ui/Card'
import { severityColor, formatDate, timeAgo } from '@/lib/utils'
import { Bot, Shield, Info, Network, ChevronLeft, Tag, Save, Plus, X } from 'lucide-react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import type { Asset } from '@/types'

function AssetMetadataEditor({ asset }: { asset: Asset }) {
  const { mutate: updateAsset, isPending: isSaving } = useUpdateAsset()
  const { mutate: addTag, isPending: isAddingTag } = useAddAssetTag()
  const { mutate: removeTag } = useRemoveAssetTag()
  const [notes, setNotes] = useState(asset.notes ?? '')
  const [deviceType, setDeviceType] = useState(asset.device_type ?? '')
  const [customFieldsText, setCustomFieldsText] = useState(
    JSON.stringify(asset.custom_fields ?? {}, null, 2),
  )
  const [tagInput, setTagInput] = useState('')
  const [editorError, setEditorError] = useState<string | null>(null)

  function handleSaveMetadata() {
    try {
      const customFields = JSON.parse(customFieldsText || '{}')
      setEditorError(null)
      updateAsset({
        id: asset.id,
        payload: {
          notes,
          device_type: deviceType || null,
          custom_fields: customFields,
        },
      })
    } catch {
      setEditorError('Custom fields must be valid JSON.')
    }
  }

  function handleAddTag() {
    const normalized = tagInput.trim().toLowerCase()
    if (!normalized) return
    addTag(
      { id: asset.id, tag: normalized },
      {
        onSuccess: () => setTagInput(''),
      },
    )
  }

  return (
    <Card>
      <CardHeader><CardTitle>Tags & Metadata</CardTitle></CardHeader>
      <CardBody className="space-y-4">
        <div>
          <p className="text-xs text-zinc-500 mb-1.5">Tags</p>
          <div className="flex flex-wrap gap-1.5 mb-2">
            {asset.tags.map((tag) => (
              <span key={tag.tag} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                {tag.tag}
                <button onClick={() => removeTag({ id: asset.id, tag: tag.tag })}>
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>
          <div className="flex gap-2">
            <input
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              placeholder="Add tag"
              className="flex-1 px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
            />
            <button
              onClick={handleAddTag}
              disabled={isAddingTag}
              className="inline-flex items-center gap-1 px-3 py-2 rounded-lg text-sm bg-sky-500 text-white"
            >
              <Plus className="w-3.5 h-3.5" /> Add
            </button>
          </div>
        </div>

        <div>
          <p className="text-xs text-zinc-500 mb-1.5">Device type</p>
          <input
            value={deviceType}
            onChange={(e) => setDeviceType(e.target.value)}
            className="w-full px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
        </div>

        <div>
          <p className="text-xs text-zinc-500 mb-1.5">Notes</p>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={4}
            className="w-full px-3 py-2 rounded-lg text-sm bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
        </div>

        <div>
          <p className="text-xs text-zinc-500 mb-1.5">Custom fields (JSON)</p>
          <textarea
            value={customFieldsText}
            onChange={(e) => setCustomFieldsText(e.target.value)}
            rows={8}
            className="w-full px-3 py-2 rounded-lg text-sm font-mono bg-gray-50 dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700"
          />
          {editorError && <p className="text-xs text-red-500 mt-1">{editorError}</p>}
        </div>

        <button
          onClick={handleSaveMetadata}
          disabled={isSaving}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm bg-sky-500 text-white"
        >
          <Save className="w-3.5 h-3.5" /> {isSaving ? 'Saving…' : 'Save'}
        </button>
      </CardBody>
    </Card>
  )
}

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>()
  const assetId = Array.isArray(params.id) ? params.id[0] : params.id
  const { data: asset, isLoading, isError } = useAsset(assetId)
  const { data: currentUser } = useCurrentUser()

  if (isLoading) return (
    <AppShell>
      <div className="max-w-5xl mx-auto space-y-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-40 rounded-xl bg-zinc-200 dark:bg-zinc-900 animate-pulse" />
        ))}
      </div>
    </AppShell>
  )

  if (isError || !asset) return (
    <AppShell>
      <div className="max-w-5xl mx-auto text-center py-20">
        <p className="text-zinc-400">Asset not found.</p>
        <Link href="/assets" className="text-sky-500 text-sm mt-2 inline-block">← Back to inventory</Link>
      </div>
    </AppShell>
  )

  const ai = (asset as any).ai_analysis
  const openPorts = (asset.ports ?? []).filter((p: any) => p.state === 'open')

  return (
    <AppShell>
      <div className="max-w-5xl mx-auto space-y-5">
        {/* Back + header */}
        <div>
          <Link href="/assets" className="inline-flex items-center gap-1 text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-white mb-3">
            <ChevronLeft className="w-4 h-4" /> Asset Inventory
          </Link>
          <div className="flex items-start justify-between flex-wrap gap-3">
            <div>
              <h2 className="text-xl font-bold text-zinc-900 dark:text-white font-mono">
                {asset.ip_address}
              </h2>
              {asset.hostname && (
                <p className="text-zinc-500 mt-0.5">{asset.hostname}</p>
              )}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <DeviceClassBadge deviceClass={ai?.device_class ?? asset.device_type} />
              <StatusBadge status={asset.status} />
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Left column: overview + ports */}
          <div className="lg:col-span-2 space-y-5">

            {/* Overview */}
            <Card>
              <CardHeader><CardTitle><Info className="w-4 h-4 inline mr-1.5" />Overview</CardTitle></CardHeader>
              <CardBody>
                <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-4 text-sm">
                  {[
                    { label: 'IP Address',  value: <span className="font-mono">{asset.ip_address}</span> },
                    { label: 'MAC Address', value: asset.mac_address || '—' },
                    { label: 'Vendor',      value: ai?.vendor ?? asset.vendor ?? '—' },
                    { label: 'OS',          value: ai?.os_guess ?? asset.os_name ?? '—' },
                    { label: 'Device Role', value: ai?.device_role ?? '—' },
                    { label: 'First Seen',  value: formatDate(asset.first_seen) },
                    { label: 'Last Seen',   value: timeAgo(asset.last_seen) },
                    { label: 'Open Ports',  value: openPorts.length },
                  ].map(({ label, value }) => (
                    <div key={label}>
                      <dt className="text-xs text-zinc-500 mb-0.5">{label}</dt>
                      <dd className="text-zinc-900 dark:text-zinc-100">{value}</dd>
                    </div>
                  ))}
                </dl>
                {/* Tags */}
                {asset.tags && asset.tags.length > 0 && (
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {asset.tags.map((t: any) => (
                      <span key={t.tag} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20">
                        <Tag className="w-3 h-3" />{t.tag}
                      </span>
                    ))}
                  </div>
                )}
              </CardBody>
            </Card>

            {/* Open Ports */}
            <Card>
              <CardHeader>
                <CardTitle><Network className="w-4 h-4 inline mr-1.5" />Open Ports ({openPorts.length})</CardTitle>
              </CardHeader>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-100 dark:border-zinc-800">
                      {['Port', 'Protocol', 'Service', 'Version / Product'].map(h => (
                        <th key={h} className="text-left px-5 py-2.5 text-xs text-zinc-500 uppercase tracking-wider font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
                    {openPorts.length === 0 ? (
                      <tr><td colSpan={4} className="px-5 py-6 text-center text-zinc-400 text-xs">No open ports found</td></tr>
                    ) : openPorts.map((p: any) => (
                      <tr key={`${p.port_number}-${p.protocol}`} className="hover:bg-gray-50 dark:hover:bg-zinc-800/50">
                        <td className="px-5 py-2.5 font-mono font-medium text-sky-600 dark:text-sky-400 tabular">{p.port_number}</td>
                        <td className="px-5 py-2.5 text-zinc-500">{p.protocol}</td>
                        <td className="px-5 py-2.5 text-zinc-700 dark:text-zinc-300">{p.service || '—'}</td>
                        <td className="px-5 py-2.5 text-zinc-500 text-xs max-w-xs truncate">{p.version || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>

            {/* AI Investigation Notes */}
            {ai?.investigation_notes && (
              <Card>
                <CardHeader>
                  <CardTitle><Bot className="w-4 h-4 inline mr-1.5 text-sky-500" />AI Investigation Notes</CardTitle>
                  <span className="text-xs text-zinc-400">{ai.ai_backend} · {ai.agent_steps} steps · <ConfidenceBadge confidence={ai.confidence} /> confidence</span>
                </CardHeader>
                <CardBody>
                  <p className="text-sm text-zinc-700 dark:text-zinc-300 leading-relaxed whitespace-pre-wrap">
                    {ai.investigation_notes}
                  </p>
                  {ai.open_services_summary?.length > 0 && (
                    <div className="mt-4">
                      <p className="text-xs text-zinc-500 mb-2 font-medium">Services identified:</p>
                      <div className="flex flex-wrap gap-1.5">
                        {ai.open_services_summary.map((s: string, i: number) => (
                          <span key={i} className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-xs font-mono text-zinc-700 dark:text-zinc-300">
                            {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </CardBody>
              </Card>
            )}
          </div>

          {/* Right column: AI summary + security findings */}
          <div className="space-y-5">
            {/* AI Summary card */}
            {ai && (
              <Card>
                <CardHeader>
                  <CardTitle><Bot className="w-4 h-4 inline mr-1.5 text-sky-500" />AI Classification</CardTitle>
                </CardHeader>
                <CardBody className="space-y-3">
                  <div>
                    <p className="text-xs text-zinc-500 mb-1">Device class</p>
                    <DeviceClassBadge deviceClass={ai.device_class} />
                  </div>
                  <div>
                    <p className="text-xs text-zinc-500 mb-1">Confidence</p>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800">
                        <div
                          className="h-1.5 rounded-full bg-sky-500 transition-all"
                          style={{ width: `${ai.confidence * 100}%` }}
                        />
                      </div>
                      <ConfidenceBadge confidence={ai.confidence} />
                    </div>
                  </div>
                  {ai.vendor && <div><p className="text-xs text-zinc-500">Vendor</p><p className="text-sm">{ai.vendor}</p></div>}
                  {ai.model  && <div><p className="text-xs text-zinc-500">Model</p><p className="text-sm">{ai.model}</p></div>}
                  {ai.device_role && <div><p className="text-xs text-zinc-500">Role</p><p className="text-sm">{ai.device_role}</p></div>}
                  {ai.suggested_tags?.length > 0 && (
                    <div>
                      <p className="text-xs text-zinc-500 mb-1.5">Suggested tags</p>
                      <div className="flex flex-wrap gap-1">
                        {ai.suggested_tags.map((t: string) => (
                          <span key={t} className="px-2 py-0.5 rounded-full text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </CardBody>
              </Card>
            )}

            {/* Security Findings */}
            {ai?.security_findings?.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle><Shield className="w-4 h-4 inline mr-1.5 text-yellow-500" />Security Findings</CardTitle>
                  <span className="text-xs text-zinc-400">{ai.security_findings.length}</span>
                </CardHeader>
                <CardBody className="space-y-3 p-0">
                  {ai.security_findings.map((f: any, i: number) => (
                    <div key={i} className={`px-5 py-3 border-b last:border-0 border-gray-100 dark:border-zinc-800`}>
                      <div className="flex items-start gap-2">
                        <span className={`mt-0.5 inline-flex px-1.5 py-0.5 rounded text-xs font-medium border ${severityColor(f.severity)}`}>
                          {f.severity}
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-zinc-900 dark:text-white">{f.title}</p>
                          <p className="text-xs text-zinc-500 mt-0.5">{f.detail}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </CardBody>
              </Card>
            )}

            {/* Notes */}
            {currentUser?.role === 'admin' ? (
              <AssetMetadataEditor key={asset.id} asset={asset} />
            ) : (
              <Card>
                <CardHeader><CardTitle>Tags & Metadata</CardTitle></CardHeader>
                <CardBody>
                  <p className="text-sm text-zinc-500">
                    Viewer accounts can inspect asset details, but editing tags and metadata requires an admin account.
                  </p>
                </CardBody>
              </Card>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  )
}
