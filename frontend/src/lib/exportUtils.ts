import type { Asset } from '@/types'

export function downloadBlob(data: Blob, filename: string) {
  const url = URL.createObjectURL(data)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function assetSlug(asset: Asset): string {
  return (asset.hostname ?? asset.ip_address).replace(/[^a-zA-Z0-9._-]/g, '_')
}

export function exportAssetJson(asset: Asset): void {
  const blob = new Blob([JSON.stringify(asset, null, 2)], { type: 'application/json' })
  downloadBlob(blob, `${assetSlug(asset)}.json`)
}

export function exportAssetCsv(asset: Asset): void {
  const ai = asset.ai_analysis ?? null
  const headers = [
    'ip_address',
    'hostname',
    'mac_address',
    'vendor',
    'os_name',
    'os_version',
    'device_type',
    'status',
    'first_seen',
    'last_seen',
    'open_ports_count',
    'tags',
    'ai_device_class',
    'ai_confidence',
    'ai_vendor',
    'ai_model',
    'ai_os_guess',
  ]
  const row = [
    asset.ip_address,
    asset.hostname ?? '',
    asset.mac_address ?? '',
    asset.vendor ?? '',
    asset.os_name ?? '',
    asset.os_version ?? '',
    asset.device_type ?? '',
    asset.status,
    asset.first_seen,
    asset.last_seen,
    String(asset.open_ports_count),
    (asset.tags ?? []).map((t) => t.tag).join(';'),
    ai?.device_class ?? '',
    ai?.confidence != null ? String(ai.confidence) : '',
    ai?.vendor ?? '',
    ai?.model ?? '',
    ai?.os_guess ?? '',
  ]
  const escape = (v: string) => `"${v.replace(/"/g, '""')}"`
  const csv = [headers.join(','), row.map(escape).join(',')].join('\n')
  downloadBlob(new Blob([csv], { type: 'text/csv' }), `${assetSlug(asset)}.csv`)
}
