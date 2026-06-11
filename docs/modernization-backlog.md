# Modernization & UX Backlog

Full-stack audit against web.dev Baseline (widely-available and newly-available, 2026) plus a UX completeness pass. No code was changed; this is a prioritized work list.

---

## List 1 — Code fixes & modernization

Scored: **speed ×3 + usability ×2 + readability ×1** (max 30). Listed highest to lowest.

### ~~1.1 Split the 2,398-line Settings component and lazy-load sections — Score 19~~

`frontend/src/app/settings/page.tsx` is a single `'use client'` file that fires ~15 admin queries on mount. Split each section into its own component loaded with `next/dynamic`, and add `content-visibility: auto` to each section wrapper so offscreen sections skip layout and paint (Baseline widely available):

```tsx
<section
  id={id}
  className="… scroll-mt-24 [content-visibility:auto] [contain-intrinsic-size:auto_600px]"
>
```

The hash-anchor sidebar nav already exists, so deferring offscreen sections is safe.

---

### ~~1.2 Drop recharts from the dashboard's critical path — Score 18~~

`frontend/src/components/dashboard/DeviceTypeChart.tsx` imports recharts (~100 KB+ gzipped) for one pie chart on the landing page. The rest of the dashboard already renders bars with pure Tailwind/CSS. Either lazy-load via `next/dynamic` or replace with a native CSS `conic-gradient()` donut — zero JS:

```css
.donut {
  background: conic-gradient(#0ea5e9 0 40%, #8b5cf6 40% 65%, #f59e0b 65% 100%);
  border-radius: 50%;
}
```

---

### 1.3 Replace the busy-wait Redis pub/sub loop in the WebSocket endpoint — Score 16

`backend/app/api/routes/websocket.py:76` polls `get_message(timeout=5.0)` and then sleeps 100 ms — every connected client wakes 10×/second forever, and events incur up to 100 ms extra latency. The async iterator blocks natively:

```python
async for message in pubsub.listen():
    if message["type"] == "message" and message["data"]:
        await websocket.send_json(json.loads(message["data"]))
```

---

### ~~1.4 Use the Popover API for hand-rolled dropdowns — Score 15~~

Three places re-implement outside-click + Escape with `document.addEventListener`:

- `frontend/src/app/assets/page.tsx:92–108` — export dropdown
- `frontend/src/app/assets/[id]/page.tsx:746–762` — export dropdown
- `frontend/src/components/assets/AssetTable.tsx:384–450` — column filter menus (no dismissal logic at all)

The `popover` attribute (Baseline widely available) gives top-layer rendering, light dismiss, and Esc for free, and deletes the listener `useEffect`s and `openFilter` state plumbing:

```tsx
<button popoverTarget="export-menu">Export <ChevronDown /></button>
<div id="export-menu" popover="auto" className="…">…menu items…</div>
```

CSS anchor positioning (Baseline newly available) can replace the manual `absolute right-0 top-full` positioning where browser support is acceptable.

---

### 1.5 Scope topology endpoint queries and reconnect the dead ETag path — Score 15

**Backend:** `backend/app/api/routes/topology.py:99–108` — the neighborhood and segment endpoints load every asset with ports and tags plus all segments and links into Python, then filter in `build_*`. Filter in SQL instead (join through `TopologyLink` for the neighborhood; `WHERE` on segment for segments).

**Frontend:** The backend computes an ETag and honors `If-None-Match` (`topology.py:65–72`), and `frontend/src/lib/api.ts:175–178` accepts an `ifNoneMatch` argument — but `useTopologyGraph` never passes it, so the 304 path is dead code. Store the previous ETag alongside the query data and send it on refetch; return the cached graph on 304.

---

### 1.6 Move the JWT from localStorage to an httpOnly cookie — Score 14

Every page is gated behind a client-side token check (`frontend/src/components/layout/AppShell.tsx:26–40`), so first paint is always a "Loading session…" spinner and nothing can be a Server Component. A cookie (set by the FastAPI login route, `SameSite=Lax`) lets Next.js middleware redirect unauthenticated users server-side, removes the login flash, and is the standard XSS-hardening move. The WebSocket can then authenticate from the cookie at handshake instead of the first-message token dance.

---

### ~~1.7 Replace the custom AlertDialog with `<dialog>` — Score 13~~

`frontend/src/components/ui/AlertDialog.tsx` claims to trap focus but doesn't — only initial focus and Escape are handled; Tab walks out into the page. Native `<dialog>.showModal()` (Baseline widely available) gives true focus trapping, background inertness, Esc handling, and `::backdrop`, and deletes the portal, key listener, and manual backdrop div:

```tsx
const ref = useRef<HTMLDialogElement>(null)
useEffect(() => { open ? ref.current?.showModal() : ref.current?.close() }, [open])
return (
  <dialog ref={ref} onClose={onCancel} className="rounded-xl p-6 backdrop:bg-black/40">
    …
  </dialog>
)
```

---

### 1.8 `content-visibility: auto` on large table rows — Score 12

`frontend/src/components/assets/AssetTable.tsx` and `frontend/src/components/scans/ScanHistory.tsx` render every row. With hundreds of assets, sorting/filtering re-renders all of them. One CSS declaration on `<tr>` skips rendering offscreen rows — native HTML/CSS replacing what would otherwise be a react-window dependency:

```css
tr {
  content-visibility: auto;
  contain-intrinsic-size: auto 45px;
}
```

---

### 1.9 Replace axios with native `fetch` — Score 11

axios is ~13 KB gzipped. Everything it's used for has a native equivalent:

- Auth header interceptor → 10-line wrapper function
- `timeout: 15_000` → `AbortSignal.timeout(15_000)`
- `responseType: 'blob'` → `response.blob()`
- `isAxiosError` checks in login, settings, and asset detail pages → one typed `ApiError` class

---

### 1.10 `Intl.RelativeTimeFormat` / `Intl.DateTimeFormat` instead of date-fns — Score 8

`frontend/src/lib/utils.ts:9` uses date-fns only for `formatDistanceToNow` and `format`. Both have been Baseline-native for years; dropping date-fns removes it from every route's bundle:

```ts
const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
rtf.format(-5, 'minute') // → "5 minutes ago"
```

---

### 1.11 `field-sizing: content` for auto-growing textareas — Score 8

The notes, custom-fields JSON, and findings-import textareas use fixed `rows={4..8}`. `field-sizing: content` with a `max-height` (Baseline newly available) auto-grows them with zero JS:

```css
textarea {
  field-sizing: content;
  max-height: 400px;
}
```

---

### 1.12 Reconnect the WebSocket on the `online` event — Score 8

`frontend/src/hooks/useWebSocket.ts:42` backs off up to 30 s. After a laptop sleep/wake the UI can sit "Disconnected" for half a minute. Reset the attempt counter and reconnect immediately when the network returns:

```ts
globalThis.addEventListener('online', connect)
```

---

### 1.13 Add `GZipMiddleware` to FastAPI — Score 7

`backend/app/main.py` has no compression. Direct API consumers (documented REST API, Home Assistant pulls, `/metrics` scrapes, topology graph JSON) get uncompressed payloads. One line:

```python
app.add_middleware(GZipMiddleware, minimum_size=1024)
```

---

### 1.14 Trigram index for asset search — Score 7

`backend/app/api/routes/assets.py:192–198` uses `ilike '%term%'` across three columns — a sequential scan per keystroke. A `pg_trgm` GIN index on `ip_address`, `hostname`, `vendor` via an Alembic migration keeps search fast as inventories grow.

---

### 1.15 `type="search"` for the search input — Score 6

`frontend/src/app/assets/page.tsx:284` uses `type="text"`. Changing to `type="search"` adds the native clear affordance and correct mobile keyboard/semantics for free.

---

### 1.16 Replace deprecated `datetime.utcnow()` — Score 2

`backend/app/modules/pfsense.py:122` uses `datetime.utcnow()`, deprecated since Python 3.12. Use `datetime.now(timezone.utc)` to match the rest of the codebase.

---

## List 2 — UX polish & existing-feature completeness

Ordered by impact. Each item is agent-actionable.

---

### ~~2.1 Asset inventory silently caps at 100 assets~~

`backend/app/api/routes/assets.py:171` defaults `limit=100` and the frontend never passes `skip`/`limit`. Networks with >100 hosts show a truncated list, and the `"{assets.length} assets"` counter in `frontend/src/app/assets/page.tsx:367` reports the truncated number as if it were the total.

**Fix:** Have `useAssets` request `limit: 500` and paginate until a short page is returned, or change the endpoint to return `{items, total}` and surface real pagination. Apply the same fix to `useDashboardAssets` — it feeds dashboard widgets and the "Enrich unresolved/unknown" target lists, which currently operate on the truncated set.

---

### ~~2.2 "Open HTML report" is broken~~

`settings/page.tsx:1739–1744` blobs `response.data` from `assetsApi.exportHtmlReport()` and opens it as HTML. But that endpoint returns a queued-job envelope `{job_id, status}` (`backend/app/api/routes/assets.py:394–396`), so the user gets a browser tab showing raw JSON.

**Fix:** Reuse the `waitForExportJob` + `downloadExportJob` flow from `frontend/src/app/assets/page.tsx:21–54` (extract it to `lib/exportUtils.ts`), then blob the downloaded content with `type: 'text/html'`.

---

### 2.3 Findings page is unreachable from the navigation

`/findings` exists but is absent from `NAV_ITEMS` in `frontend/src/components/layout/Sidebar.tsx:14–22`. Additionally, `PAGE_TITLES` in `frontend/src/components/layout/Header.tsx:13–20` is missing `/findings` and `/inventory` — the header falls back to "Argus" on both pages.

**Fix:** Add a Findings nav item (e.g., `ShieldAlert` icon) and add the two missing title entries to `PAGE_TITLES`.

---

### 2.4 Findings import crashes on invalid JSON

`frontend/src/app/findings/page.tsx:22–26` calls `JSON.parse(importJson)` with no try/catch — malformed input throws an unhandled exception and the textarea clears on success with no confirmation.

**Fix:** Wrap in try/catch and show an inline error on failure. On success, show "N findings imported" using the count from the mutation response.

---

### 2.5 Scan form error state is dead code

`frontend/src/app/scans/page.tsx:43` — `error` is only ever set to `null`, so the red input border and error `<p>` never render. A failed enqueue shows only a generic "Failed to enqueue".

**Fix:** Validate the target client-side (IP/CIDR regex) before submitting. Surface the backend's `detail` string in `onError` using the same `getErrorDetail` pattern used in the asset detail page.

---

### 2.6 Findings severity badge ignores severity

`frontend/src/app/findings/page.tsx:83` hardcodes `bg-red-500/10 text-red-600` for every severity level.

**Fix:** Use the existing `severityColor()` utility from `frontend/src/lib/utils.ts:38`, which is already used on the asset detail page.

---

### 2.7 Column filter menus in AssetTable don't dismiss

The per-column filter popovers in `frontend/src/components/assets/AssetTable.tsx:384–450` stay open until you click the chevron again or pick an option — no outside-click handler, no Escape, unlike the Export menu on the same page.

**Fix:** Apply the Popover API (see 1.4) or replicate the export menu's `document.addEventListener` listeners for these menus.

---

### 2.8 Select-all checkbox lacks an indeterminate state

`frontend/src/components/assets/AssetTable.tsx:333–341` — when some but not all visible rows are selected, the header checkbox shows as unchecked.

**Fix:**
```tsx
ref={(el) => {
  if (el) el.indeterminate = someSelected && !allVisibleSelected
}}
```

---

### 2.9 Help tooltips are mouse-only

`HelpTooltip` in `frontend/src/app/settings/page.tsx:210–219` uses `group-hover` — invisible to keyboard and touch users.

**Fix:** Make the trigger a focusable `<button>` with `aria-label` and show the tooltip on `group-focus-within` as well, or convert to `popover="hint"`. Add `role="tooltip"` to the tooltip element.

---

### 2.10 Sortable headers and icon buttons lack ARIA

- `frontend/src/components/assets/AssetTable.tsx:343–369`: missing `aria-sort` on the active `<th>` and `aria-label` on filter chevron buttons.
- `frontend/src/components/layout/Header.tsx:78`: refresh, theme, and sign-out buttons use only `title` — replace with `aria-label`.
- Decorative lucide icons throughout should get `aria-hidden="true"`.

---

### 2.11 No mobile layout

`frontend/src/components/layout/Sidebar.tsx` is `fixed` and `frontend/src/components/layout/AppShell.tsx:46–49` hardcodes `ml-16`/`ml-56`. On a phone the sidebar permanently eats a third of the viewport.

**Fix:** Below the `md:` breakpoint, collapse the sidebar to the icon rail by default or convert it to an overlay drawer toggled from the header.

---

### 2.12 Relative timestamps go stale

`timeAgo` values in the asset table, scan history, and dashboard never update while the WebSocket suppresses refetching (`refetchInterval: wsConnected ? false : …`).

**Fix:** Add a 30–60 s ticker (one `setInterval` in a shared hook, or a refetch-independent re-render) so "Last Seen" stays accurate during long sessions.

---

### 2.13 Asset detail "Back" button can exit the app

`frontend/src/app/assets/[id]/page.tsx:792–797` uses `router.back()`. On a deep link (e.g., opened from a notification) it navigates to the previous site or a blank tab.

**Fix:** Replace with `<Link href="/assets">` — URL params the assets page already syncs can preserve filter state.

---

### 2.14 Export feedback is easy to miss and never clears

On the assets page, export status renders as small grey text inside the filter bar (`frontend/src/app/assets/page.tsx:360–364`) and persists indefinitely. Failures look identical to progress at a glance.

**Fix:** Render as a dismissible status strip using the amber/emerald callout patterns already used on the scans page. Auto-clear success after a few seconds and style failures red. The 2-second `waitForExportJob` polling could also short-circuit on the existing `scan_complete` WebSocket event.

---

### 2.15 Truncated cells hide data with no recourse

Hostname (`max-w-32`) and vendor/OS (`max-w-36`) cells in `frontend/src/components/assets/AssetTable.tsx:503–518` clip without a `title` attribute.

**Fix:** Add `title={asset.hostname}` (and vendor/OS equivalents) to the truncating `<span>` elements.

---

### 2.16 WS-disconnected staleness handling is inconsistent

The assets page shows an "Updated Xs ago + refresh" affordance when the socket is down (`frontend/src/app/assets/page.tsx:368–382`). The dashboard, scans, and topology pages — which depend on the same live events — give no equivalent cue beyond the small sidebar "Disconnected" label.

**Fix:** Extract the stale-indicator into a shared component and render it on the other live pages.
