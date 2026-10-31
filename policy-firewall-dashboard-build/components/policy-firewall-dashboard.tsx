'use client'

import { useMemo, useState, type FormEvent } from 'react'
import useSWR from 'swr'
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  ArrowUpRightFromSquare,
  Ban,
  Bell,
  BookOpen,
  ChevronRight,
  CircleHelp,
  Clock3,
  Code2,
  Database,
  FileKey2,
  Fingerprint,
  Globe2,
  LockKeyhole,
  Moon,
  Plus,
  Radio,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Terminal,
  TriangleAlert,
  X,
  Zap,
} from 'lucide-react'

type Decision = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL'
type Risk = 'LOW' | 'MEDIUM' | 'HIGH'

type Policy = {
  id: string
  name: string
  clause: string
  enabled: boolean
  tone: 'emerald' | 'cyan' | 'amber' | 'rose'
}

type AuditEvent = {
  id: string
  timestamp: string
  risk: Risk
  decision: Decision
  tool: string
  path: string
  payload: string
  destination: string
  reasoning: string
  policy: string
  source?: 'preview'
}

const API = 'http://localhost:5000/api'

const seedPolicies: Policy[] = [
  { id: 'p1', name: 'Secrets stay local', clause: 'Deny reads of .env, credentials, and private keys', enabled: true, tone: 'rose' },
  { id: 'p2', name: 'Workspace read access', clause: 'Allow read-only access to project documentation', enabled: true, tone: 'emerald' },
  { id: 'p3', name: 'PII egress review', clause: 'Require approval before personal data leaves the workspace', enabled: true, tone: 'amber' },
  { id: 'p4', name: 'External destinations', clause: 'Review outbound requests to untrusted destinations', enabled: true, tone: 'cyan' },
]

const seedEvents: AuditEvent[] = [
  {
    id: 'evt-01', timestamp: 'just now', risk: 'HIGH', decision: 'REQUIRE_APPROVAL', tool: 'http.post', path: '/exports/customers.csv', payload: 'email, full_name, account_id …', destination: 'https://api.vendor-cloud.io/ingest', reasoning: 'This request sends identifiable customer data to an external service and needs a human review.', policy: 'PII egress review · clause 3.2',
  },
  {
    id: 'evt-02', timestamp: '2 min ago', risk: 'LOW', decision: 'ALLOW', tool: 'fs.read', path: '/workspace/README.md', payload: '## Getting started · install & run …', destination: 'local workspace', reasoning: 'The agent is reading permitted project documentation without sharing data externally.', policy: 'Workspace read access · clause 1.1',
  },
  {
    id: 'evt-03', timestamp: '4 min ago', risk: 'HIGH', decision: 'DENY', tool: 'fs.read', path: '/workspace/.env', payload: 'DATABASE_URL=•••••••• · API_KEY=••••', destination: 'local workspace', reasoning: 'Secret files are blocked from agent access to prevent accidental credential exposure.', policy: 'Secrets stay local · clause 2.4',
  },
  {
    id: 'evt-04', timestamp: '8 min ago', risk: 'MEDIUM', decision: 'ALLOW', tool: 'fs.list', path: '/workspace/src', payload: '12 files · 4 directories', destination: 'local workspace', reasoning: 'Listing project source files is permitted and does not expose sensitive file contents.', policy: 'Workspace read access · clause 1.1',
  },
]

async function fetchJson(url: string, init?: RequestInit) {
  const response = await fetch(url, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })
  if (!response.ok) throw new Error(`API returned ${response.status}`)
  return response.json()
}

function unwrapArray(value: unknown, keys: string[]) {
  if (Array.isArray(value)) return value
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>
    for (const key of keys) if (Array.isArray(record[key])) return record[key] as unknown[]
  }
  return []
}

function toPolicies(value: unknown): Policy[] {
  const rows = unwrapArray(value, ['policies', 'data', 'items'])
  if (!rows.length) {
    const hasEmptyCollection = Boolean(value && typeof value === 'object' && ['policies', 'data', 'items'].some((key) => Array.isArray((value as Record<string, unknown>)[key])))
    return hasEmptyCollection ? [] : seedPolicies
  }
  return rows.map((row, index) => {
    const item = row as Record<string, unknown>
    return {
      id: String(item.id ?? `policy-${index}`),
      name: String(item.name ?? item.title ?? item.key ?? `Policy ${index + 1}`),
      clause: String(item.clause ?? item.description ?? item.rule ?? 'Policy clause provided by the governance API'),
      enabled: item.enabled !== false && item.active !== false,
      tone: (['rose', 'emerald', 'amber', 'cyan'][index % 4]) as Policy['tone'],
    }
  })
}

function toEvents(value: unknown): AuditEvent[] {
  const rows = unwrapArray(value, ['logs', 'events', 'data', 'items'])
  if (!rows.length) {
    const hasEmptyCollection = Boolean(value && typeof value === 'object' && ['logs', 'events', 'data', 'items'].some((key) => Array.isArray((value as Record<string, unknown>)[key])))
    return hasEmptyCollection ? [] : seedEvents
  }
  return rows.map((row, index) => {
    const item = row as Record<string, unknown>
    const rawDecision = String(item.decision ?? item.action ?? item.result ?? 'ALLOW').toUpperCase()
    const decision: Decision = rawDecision.includes('APPROVAL') || rawDecision.includes('PENDING') ? 'REQUIRE_APPROVAL' : rawDecision.includes('DENY') || rawDecision.includes('BLOCK') ? 'DENY' : 'ALLOW'
    const rawRisk = String(item.risk ?? item.severity ?? 'MEDIUM').toUpperCase()
    return {
      id: String(item.id ?? item.request_id ?? `api-${index}`),
      timestamp: String(item.timestamp ?? item.created_at ?? item.time ?? 'recently'),
      risk: (['LOW', 'MEDIUM', 'HIGH'].includes(rawRisk) ? rawRisk : 'MEDIUM') as Risk,
      decision,
      tool: String(item.tool ?? item.action_tool ?? 'unknown.tool'),
      path: String(item.path ?? item.requested_path ?? item.resource ?? '—'),
      payload: String(item.payload ?? item.payload_snippet ?? item.input ?? 'No payload provided'),
      destination: String(item.destination ?? item.target ?? item.target_destination ?? 'local workspace'),
      reasoning: String(item.reasoning ?? item.reason ?? item.explanation ?? 'Decision returned by the governance evaluation service.'),
      policy: String(item.policy ?? item.matched_policy ?? item.policy_clause ?? 'No policy clause returned'),
    }
  })
}

const decisionStyles: Record<Decision, { label: string; icon: typeof ShieldCheck; className: string }> = {
  ALLOW: { label: 'ALLOW', icon: ShieldCheck, className: 'border-orange-400/20 bg-orange-400/[0.08] text-orange-300' },
  DENY: { label: 'DENY', icon: Ban, className: 'border-orange-400/20 bg-orange-400/[0.08] text-orange-300' },
  REQUIRE_APPROVAL: { label: 'REVIEW', icon: CircleHelp, className: 'border-orange-300/20 bg-orange-300/[0.08] text-orange-200' },
}

const riskStyles: Record<Risk, string> = {
  LOW: 'border-orange-400/15 bg-orange-400/[0.06] text-orange-300/90',
  MEDIUM: 'border-orange-300/15 bg-orange-300/[0.06] text-orange-200/90',
  HIGH: 'border-orange-400/15 bg-orange-400/[0.06] text-orange-300/90',
}

function IconButton({ label, children, onClick }: { label: string; children: React.ReactNode; onClick?: () => void }) {
  return <button aria-label={label} onClick={onClick} className="grid size-9 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.025] text-slate-400 transition hover:border-white/15 hover:text-slate-100">{children}</button>
}

function SectionHeading({ eyebrow, title, icon: Icon, right }: { eyebrow?: string; title: string; icon: typeof Shield; right?: React.ReactNode }) {
  return (
    <div className="mb-4 flex items-center justify-between gap-3">
      <div className="flex items-center gap-3">
        <span className="grid size-8 place-items-center rounded-lg border border-orange-300/10 bg-orange-300/[0.05] text-orange-300"><Icon className="size-4" /></span>
        <div>
          {eyebrow && <p className="text-[9px] font-semibold uppercase tracking-[0.22em] text-slate-600">{eyebrow}</p>}
          <h2 className="text-[13px] font-semibold tracking-wide text-slate-100">{title}</h2>
        </div>
      </div>
      {right}
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color, note, trend }: { label: string; value: number; icon: typeof Activity; color: string; note: string; trend?: 'up' | 'down' }) {
  return (
    <article className="group relative overflow-hidden rounded-xl border border-white/[0.075] bg-[#0c1112] px-4 py-4 transition hover:border-white/[0.13] sm:px-5">
      <div className={`absolute right-0 top-0 h-20 w-20 rounded-full opacity-[0.07] blur-2xl ${color}`} />
      <div className="relative flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500">{label}</p>
          <p className="mt-2 font-mono text-[27px] font-medium leading-none tracking-tight text-slate-100">{value.toString().padStart(2, '0')}</p>
          <p className="mt-2 flex items-center gap-1.5 text-[10px] text-slate-500">
            {trend === 'down' ? <ArrowDownRight className="size-3 text-orange-400" /> : trend === 'up' ? <ArrowUpRight className="size-3 text-orange-400" /> : <span className="size-1 rounded-full bg-slate-600" />}
            {note}
          </p>
        </div>
        <span className={`grid size-9 shrink-0 place-items-center rounded-lg border border-white/[0.07] bg-white/[0.025] ${color.replace('bg-', 'text-')}`}><Icon className="size-[17px]" /></span>
      </div>
    </article>
  )
}

function PolicyPanel({ policies, onAdd, onToggle }: { policies: Policy[]; onAdd: (name: string) => void; onToggle: (id: string) => void }) {
  const [name, setName] = useState('')
  const handleAdd = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!name.trim()) return
    onAdd(name.trim())
    setName('')
  }
  return (
    <section className="rounded-xl border border-white/[0.075] bg-[#0c1112] p-4 sm:p-5">
      <SectionHeading eyebrow="POLICY ENGINE" title="Active security policies" icon={LockKeyhole} right={<span className="rounded-md border border-orange-400/15 bg-orange-400/[0.05] px-2 py-1 font-mono text-[10px] text-orange-300">{policies.filter((policy) => policy.enabled).length} ACTIVE</span>} />
      <div className="flex flex-col gap-2">
        {policies.map((policy) => (
          <button key={policy.id} type="button" onClick={() => onToggle(policy.id)} aria-pressed={policy.enabled} className="group flex w-full items-start gap-3 rounded-lg border border-white/[0.055] bg-[#080c0d] px-3 py-3 text-left transition hover:border-white/[0.12]">
            <span className={`mt-0.5 size-1.5 shrink-0 rounded-full ${policy.enabled ? policy.tone === 'rose' ? 'bg-orange-400 shadow-[0_0_9px_#fb923c]' : policy.tone === 'amber' ? 'bg-orange-300 shadow-[0_0_9px_#fdba74]' : policy.tone === 'cyan' ? 'bg-orange-300 shadow-[0_0_9px_#fb923c]' : 'bg-orange-300 shadow-[0_0_9px_#fb923c]' : 'bg-slate-700'}`} />
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-2 text-[11px] font-medium text-slate-200">{policy.name}<span className="font-mono text-[8px] uppercase tracking-widest text-slate-600">{policy.enabled ? 'ON' : 'OFF'}</span></span>
              <span className="mt-1 block text-[10px] leading-relaxed text-slate-500">{policy.clause}</span>
            </span>
            <ChevronRight className="mt-0.5 size-3.5 shrink-0 text-slate-700 transition group-hover:text-slate-400" />
          </button>
        ))}
      </div>
      <form onSubmit={handleAdd} className="mt-3 flex gap-2">
        <label htmlFor="new-policy" className="sr-only">Add a local policy</label>
        <input id="new-policy" value={name} onChange={(event) => setName(event.target.value)} placeholder="Add a local policy clause…" className="h-9 min-w-0 flex-1 rounded-lg border border-white/[0.08] bg-[#080c0d] px-3 text-[11px] text-slate-200 outline-none placeholder:text-slate-600 focus:border-orange-300/30 focus:ring-2 focus:ring-orange-300/10" />
        <button type="submit" aria-label="Add policy" className="grid size-9 shrink-0 place-items-center rounded-lg border border-orange-300/20 bg-orange-300/[0.08] text-orange-200 transition hover:bg-orange-300/[0.14]"><Plus className="size-4" /></button>
      </form>
      <p className="mt-2 text-[9px] text-slate-600">New clauses are session-only; the API currently exposes policy reads.</p>
    </section>
  )
}

function Simulator({ onEvaluate, busy }: { onEvaluate: (input: { tool: string; path: string; payload: string; destination: string }) => void; busy: boolean }) {
  const [form, setForm] = useState({ tool: 'fs.read', path: '/workspace/README.md', payload: 'Read the project setup guide', destination: 'local workspace' })
  const [preset, setPreset] = useState('')
  const update = (key: keyof typeof form, value: string) => setForm((current) => ({ ...current, [key]: value }))
  const presets = [
    { label: 'Test .env Access', outcome: 'DENY', values: { tool: 'fs.read', path: '/workspace/.env', payload: 'Read environment secrets', destination: 'local workspace' } },
    { label: 'Test Read Readme', outcome: 'ALLOW', values: { tool: 'fs.read', path: '/workspace/README.md', payload: 'Read project documentation', destination: 'local workspace' } },
    { label: 'Test Exfiltrate PII', outcome: 'REVIEW', values: { tool: 'http.post', path: '/exports/customers.csv', payload: 'email, full_name, account_id', destination: 'https://api.vendor-cloud.io/ingest' } },
  ]
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); onEvaluate(form) }
  return (
    <section className="rounded-xl border border-white/[0.075] bg-[#0c1112] p-4 sm:p-5">
      <SectionHeading eyebrow="SANDBOX" title="Agent action simulator" icon={Terminal} right={<span className="flex items-center gap-1.5 text-[9px] font-medium uppercase tracking-wider text-orange-300/80"><Zap className="size-3" />Dry run</span>} />
      <div className="mb-4 grid grid-cols-1 gap-1.5 sm:grid-cols-3 xl:grid-cols-1 2xl:grid-cols-3">
        {presets.map((item) => <button type="button" key={item.label} onClick={() => { setForm(item.values); setPreset(item.label) }} className={`rounded-md border px-2 py-2 text-left transition ${preset === item.label ? 'border-orange-300/25 bg-orange-300/[0.06]' : 'border-white/[0.055] bg-[#080c0d] hover:border-white/[0.12]'}`}>
          <span className="block truncate text-[9px] font-medium text-slate-300">{item.label}</span><span className={`mt-1 block font-mono text-[8px] tracking-wider ${item.outcome === 'DENY' ? 'text-orange-300' : item.outcome === 'ALLOW' ? 'text-orange-300' : 'text-orange-200'}`}>EXPECTED: {item.outcome}</span>
        </button>)}
      </div>
      <form onSubmit={submit} className="flex flex-col gap-3">
        {([
          ['tool', 'Tool', 'e.g. fs.read'], ['path', 'Requested path', '/workspace/README.md'], ['payload', 'Payload', 'Describe the requested action'], ['destination', 'Destination', 'local workspace or https://…'],
        ] as const).map(([key, label, placeholder]) => <div key={key} className="flex flex-col gap-1.5">
          <label htmlFor={`sim-${key}`} className="text-[9px] font-semibold uppercase tracking-[0.13em] text-slate-500">{label}</label>
          <input id={`sim-${key}`} value={form[key]} onChange={(event) => update(key, event.target.value)} placeholder={placeholder} required className="h-9 rounded-lg border border-white/[0.07] bg-[#080c0d] px-3 font-mono text-[10px] text-slate-200 outline-none placeholder:font-sans placeholder:text-slate-700 focus:border-orange-300/30 focus:ring-2 focus:ring-orange-300/10" />
        </div>)}
        <button type="submit" disabled={busy} className="mt-1 flex h-10 items-center justify-center gap-2 rounded-lg border border-orange-300/20 bg-orange-300/[0.09] text-[11px] font-semibold tracking-wide text-orange-200 transition hover:bg-orange-300/[0.15] disabled:cursor-wait disabled:opacity-60"><Send className="size-3.5" />{busy ? 'Evaluating request…' : 'Evaluate action'}</button>
      </form>
    </section>
  )
}

function ActivityCard({ event, resolution, onResolve }: { event: AuditEvent; resolution?: 'APPROVED' | 'DENIED'; onResolve: (id: string, decision: 'APPROVED' | 'DENIED') => void }) {
  const finalDecision: Decision = resolution ? resolution === 'APPROVED' ? 'ALLOW' : 'DENY' : event.decision
  const visual = decisionStyles[finalDecision]
  const DecisionIcon = visual.icon
  return (
    <article className="relative overflow-hidden rounded-xl border border-white/[0.075] bg-[#0c1112] transition hover:border-white/[0.12]">
      <div className={`absolute inset-y-0 left-0 w-px ${finalDecision === 'ALLOW' ? 'bg-orange-300/50' : finalDecision === 'DENY' ? 'bg-orange-300/50' : 'bg-orange-200/60'}`} />
      <div className="p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="flex items-center gap-1 rounded-md border border-white/[0.07] bg-white/[0.025] px-2 py-1 font-mono text-[9px] text-slate-400"><Clock3 className="size-3 text-slate-500" />{event.timestamp}</span>
            <span className={`rounded-md border px-2 py-1 font-mono text-[9px] tracking-wide ${riskStyles[event.risk]}`}>{event.risk} RISK</span>
            {event.source === 'preview' && <span className="rounded-md border border-orange-300/15 bg-orange-300/[0.05] px-2 py-1 font-mono text-[8px] tracking-wider text-orange-200/80">LOCAL PREVIEW</span>}
          </div>
          <span className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 font-mono text-[9px] font-semibold tracking-wider ${visual.className}`}><DecisionIcon className="size-3.5" />{resolution ? finalDecision : visual.label}</span>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Detail label="ACTION TOOL" value={event.tool} icon={Code2} mono />
          <Detail label="REQUESTED PATH" value={event.path} icon={FileKey2} mono />
          <Detail label="PAYLOAD SNIPPET" value={event.payload} icon={Database} />
          <Detail label="TARGET DESTINATION" value={event.destination} icon={Globe2} mono />
        </div>
        <div className="mt-4 grid gap-3 border-t border-white/[0.055] pt-3 md:grid-cols-[1.2fr_1fr]">
          <div className="flex items-start gap-2.5"><span className="mt-0.5 text-orange-300"><Fingerprint className="size-3.5" /></span><div><p className="text-[8px] font-semibold uppercase tracking-[0.16em] text-slate-600">Gemma 4 reasoning</p><p className="mt-1 text-[10px] leading-relaxed text-slate-400">{resolution ? `A reviewer ${resolution.toLowerCase()} this action for the current session.` : event.reasoning}</p></div></div>
          <div className="flex items-start gap-2.5"><span className="mt-0.5 text-orange-300"><BookOpen className="size-3.5" /></span><div><p className="text-[8px] font-semibold uppercase tracking-[0.16em] text-slate-600">Matched policy</p><p className="mt-1 text-[10px] leading-relaxed text-slate-300">{event.policy}</p></div></div>
        </div>
        {!resolution && event.decision === 'REQUIRE_APPROVAL' && <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-orange-200/10 bg-orange-200/[0.035] px-3 py-2.5">
          <p className="flex items-center gap-2 text-[10px] text-orange-100/75"><TriangleAlert className="size-3.5 text-orange-200" />Human review required before this action can proceed.</p>
          <div className="flex gap-2"><button onClick={() => onResolve(event.id, 'DENIED')} className="rounded-md border border-orange-300/15 px-3 py-1.5 text-[9px] font-medium text-orange-200 transition hover:bg-orange-300/[0.08]">Deny</button><button onClick={() => onResolve(event.id, 'APPROVED')} className="rounded-md border border-orange-300/20 bg-orange-300/[0.08] px-3 py-1.5 text-[9px] font-medium text-orange-200 transition hover:bg-orange-300/[0.14]">Approve action</button></div>
        </div>}
      </div>
    </article>
  )
}

function Detail({ label, value, icon: Icon, mono }: { label: string; value: string; icon: typeof Activity; mono?: boolean }) {
  return <div className="min-w-0"><p className="flex items-center gap-1.5 text-[8px] font-semibold tracking-[0.13em] text-slate-600"><Icon className="size-3" />{label}</p><p title={value} className={`mt-1.5 truncate text-[10px] text-slate-300 ${mono ? 'font-mono' : ''}`}>{value}</p></div>
}

function localEvaluate(input: { tool: string; path: string; payload: string; destination: string }, policies: Policy[]): AuditEvent {
  const haystack = `${input.path} ${input.payload} ${input.destination}`.toLowerCase()
  const isSecret = /\.env|credential|private.?key|secret/.test(haystack)
  const isPii = /pii|customer|email|personal|account_id|full_name/.test(haystack) && /https?:|external|vendor|export|upload|post/.test(`${haystack} ${input.tool}`.toLowerCase())
  const decision: Decision = isSecret ? 'DENY' : isPii ? 'REQUIRE_APPROVAL' : 'ALLOW'
  const policy = isSecret ? policies.find((item) => /secret|env|credential/i.test(item.name + item.clause)) : isPii ? policies.find((item) => /pii|personal|egress|approval/i.test(item.name + item.clause)) : policies.find((item) => /read|workspace|documentation/i.test(item.name + item.clause))
  const risk: Risk = isSecret || isPii ? 'HIGH' : /http|write|delete|exec/i.test(input.tool) ? 'MEDIUM' : 'LOW'
  const reasoning = isSecret ? 'Secret files are blocked to prevent credentials from being exposed to the agent.' : isPii ? 'This request may send personal data outside the workspace and needs a human review.' : 'This action matches the workspace access rules and does not appear to expose sensitive data.'
  return { id: `local-${Date.now()}`, timestamp: 'just now', risk, decision, tool: input.tool, path: input.path, payload: input.payload, destination: input.destination, reasoning, policy: policy ? `${policy.name} · local preview` : 'Default workspace access · local preview', source: 'preview' }
}

export function PolicyFirewallDashboard() {
  const { data: policyResponse, error: policyError, isLoading: policiesLoading, mutate: mutatePolicies } = useSWR(`${API}/policies`, fetchJson, { fallbackData: { policies: seedPolicies }, refreshInterval: 10000, revalidateOnFocus: true })
  const { data: logsResponse, error: logsError, isLoading: logsLoading, mutate: mutateLogs } = useSWR(`${API}/logs`, fetchJson, { fallbackData: { logs: seedEvents }, refreshInterval: 5000, revalidateOnFocus: true })
  const [sessionPolicies, setSessionPolicies] = useState<Policy[]>([])
  const [policyOverrides, setPolicyOverrides] = useState<Record<string, boolean>>({})
  const [sessionEvents, setSessionEvents] = useState<AuditEvent[]>([])
  const [resolutions, setResolutions] = useState<Record<string, 'APPROVED' | 'DENIED'>>({})
  const [evaluating, setEvaluating] = useState(false)
  const [lastRefresh, setLastRefresh] = useState('LIVE · 5S')
  const [notice, setNotice] = useState('')
  const [theme, setTheme] = useState<'orange' | 'black'>('orange')
  const policies = useMemo(() => [...sessionPolicies, ...toPolicies(policyResponse)].map((policy) => ({ ...policy, enabled: policyOverrides[policy.id] ?? policy.enabled })), [sessionPolicies, policyOverrides, policyResponse])
  const apiEvents = useMemo(() => toEvents(logsResponse), [logsResponse])
  const events = useMemo(() => [...sessionEvents, ...apiEvents].sort((a, b) => {
    const aTime = Date.parse(a.timestamp)
    const bTime = Date.parse(b.timestamp)
    return Number.isFinite(aTime) && Number.isFinite(bTime) ? bTime - aTime : 0
  }), [apiEvents, sessionEvents])
  const totalRequests = events.length
  const allowed = events.filter((event) => (resolutions[event.id] ? resolutions[event.id] === 'APPROVED' : event.decision === 'ALLOW')).length
  const blocked = events.filter((event) => (resolutions[event.id] ? resolutions[event.id] === 'DENIED' : event.decision === 'DENY')).length
  const pending = events.filter((event) => event.decision === 'REQUIRE_APPROVAL' && !resolutions[event.id]).length
  const isOffline = Boolean(policyError || logsError)

  const refresh = async () => {
    await Promise.all([mutatePolicies(), mutateLogs()])
    setLastRefresh('JUST UPDATED')
    window.setTimeout(() => setLastRefresh('LIVE · 5S'), 2400)
  }

  const addPolicy = (name: string) => setSessionPolicies((current) => [{ id: `local-policy-${Date.now()}`, name, clause: 'Custom session clause · review and connect a policy write endpoint to persist', enabled: true, tone: 'cyan' }, ...current])
  const togglePolicy = (id: string) => setPolicyOverrides((current) => {
    const policy = policies.find((item) => item.id === id)
    return policy ? { ...current, [id]: !policy.enabled } : current
  })

  const evaluate = async (input: { tool: string; path: string; payload: string; destination: string }) => {
    setEvaluating(true)
    setNotice('')
    try {
      await fetchJson(`${API}/evaluate`, { method: 'POST', body: JSON.stringify(input) })
      setNotice('Request evaluated by the local governance API.')
      await mutateLogs()
    } catch {
      const localEvent = localEvaluate(input, policies)
      setSessionEvents((current) => [localEvent, ...current])
      setNotice('API unavailable — this request used the local preview evaluator.')
    } finally {
      setEvaluating(false)
    }
  }

  const resolve = (id: string, decision: 'APPROVED' | 'DENIED') => {
    setResolutions((current) => ({ ...current, [id]: decision }))
    setNotice(`${decision === 'APPROVED' ? 'Approved' : 'Denied'} for this session. Connect an approval endpoint to persist reviewer actions.`)
  }

  return (
    <main data-theme={theme} className="min-h-screen overflow-x-hidden bg-[#070a0b] text-slate-100 selection:bg-orange-300/20 selection:text-orange-100">
      <div className="pointer-events-none fixed inset-0 opacity-[0.035] [background-image:linear-gradient(rgba(255,255,255,.16)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,.16)_1px,transparent_1px)] [background-size:56px_56px]" />
      <div className="relative mx-auto max-w-[1600px] px-4 pb-10 sm:px-6 lg:px-8">
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-white/[0.07] py-5">
          <div className="flex min-w-0 items-center gap-3.5">
            <div className="relative grid size-10 shrink-0 place-items-center rounded-xl border border-orange-300/20 bg-orange-300/[0.06] text-orange-200 shadow-[0_0_28px_rgba(249,115,22,0.1)]"><Shield className="size-5" /><span className="absolute -right-1 -top-1 size-2.5 rounded-full border-2 border-[#070a0b] bg-orange-300" /></div>
            <div className="min-w-0"><p className="truncate text-[15px] font-semibold tracking-tight text-slate-100 sm:text-[17px]">Policy Firewall</p><p className="mt-0.5 truncate text-[9px] font-medium uppercase tracking-[0.2em] text-slate-500">Local AI Governance Gatekeeper</p></div>
          </div>
          <div className="flex items-center gap-2.5">
            <div className={`hidden items-center gap-2 rounded-lg border px-3 py-2 sm:flex ${isOffline ? 'border-orange-200/15 bg-orange-200/[0.045]' : 'border-orange-300/15 bg-orange-300/[0.045]'}`}><span className={`relative size-1.5 rounded-full ${isOffline ? 'bg-orange-300' : 'bg-orange-300'}`}><span className={`absolute inset-0 animate-ping rounded-full ${isOffline ? 'bg-orange-300/70' : 'bg-orange-300/70'}`} /></span><span className={`text-[9px] font-medium tracking-wide ${isOffline ? 'text-orange-100/80' : 'text-orange-100/80'}`}>{isOffline ? 'LOCAL PREVIEW · API OFFLINE' : 'Air-Gapped Gemma 4 Engine Active'}</span></div>
            <IconButton label="Refresh policies and activity" onClick={refresh}><RefreshCw className="size-4" /></IconButton>
            <IconButton label="Notifications"><Bell className="size-4" /></IconButton>
            <IconButton label={theme === 'orange' ? 'Switch to pure black theme' : 'Switch to orange theme'} onClick={() => setTheme((current) => current === 'orange' ? 'black' : 'orange')}>
              {theme === 'orange' ? <Moon className="size-4" /> : <Sun className="size-4" />}
            </IconButton>
            <div className="ml-1 hidden h-8 w-px bg-white/[0.08] sm:block" />
            <div className="hidden items-center gap-2 sm:flex"><span className="grid size-7 place-items-center rounded-full border border-orange-300/15 bg-orange-300/[0.06] font-mono text-[9px] text-orange-200">PF</span><span className="text-[10px] text-slate-400">Operator</span></div>
          </div>
        </header>

        <div className="mt-5 flex flex-wrap items-end justify-between gap-3">
          <div><div className="flex items-center gap-2 text-[9px] font-semibold uppercase tracking-[0.2em] text-slate-600"><span className="text-orange-300/80">SECURITY OVERVIEW</span><span className="text-slate-700">/</span><span>GOVERNANCE GATEWAY</span></div><h1 className="mt-2 text-[19px] font-medium tracking-tight text-slate-100 sm:text-[22px]">Control plane <span className="font-normal text-slate-500">/ real-time overview</span></h1></div>
          <div className="flex items-center gap-2 text-[9px] font-mono text-slate-500"><Radio className={`size-3 ${isOffline ? 'text-orange-200' : 'text-orange-300'}`} />{isOffline ? 'PREVIEW DATA' : lastRefresh}<span className="text-slate-700">·</span>{policiesLoading || logsLoading ? 'SYNCING' : 'AUDIT STREAM'}</div>
        </div>

        <section aria-label="Request summary" className="mt-5 grid grid-cols-2 gap-3 xl:grid-cols-4">
          <StatCard label="Total requests" value={totalRequests} icon={Activity} color="bg-orange-300" note="Observed in current stream" />
          <StatCard label="Allowed count" value={allowed} icon={ShieldCheck} color="bg-orange-300" note="Within policy boundaries" />
          <StatCard label="Blocked count" value={blocked} icon={ShieldAlert} color="bg-orange-300" note="Policy prevented access" />
          <StatCard label="Pending approvals" value={pending} icon={Clock3} color="bg-orange-200" note="Waiting for human review" />
        </section>

        {notice && <div role="status" className="mt-4 flex items-start justify-between gap-3 rounded-lg border border-orange-300/15 bg-orange-300/[0.045] px-3 py-2.5 text-[10px] text-orange-100/80"><span className="flex items-center gap-2"><ArrowUpRightFromSquare className="mt-0.5 size-3.5 shrink-0 text-orange-200" />{notice}</span><button onClick={() => setNotice('')} aria-label="Dismiss notice" className="text-orange-100/50 hover:text-orange-100"><X className="size-3.5" /></button></div>}

        <div className="mt-5 grid items-start gap-5 xl:grid-cols-[350px_minmax(0,1fr)] 2xl:grid-cols-[370px_minmax(0,1fr)]">
          <aside className="flex flex-col gap-5">
            <PolicyPanel policies={policies} onAdd={addPolicy} onToggle={togglePolicy} />
            <Simulator onEvaluate={evaluate} busy={evaluating} />
            <div className="flex items-center gap-3 rounded-xl border border-orange-300/10 bg-orange-300/[0.025] px-4 py-3"><span className="grid size-8 shrink-0 place-items-center rounded-lg border border-orange-300/10 bg-orange-300/[0.05] text-orange-200"><ShieldCheck className="size-4" /></span><p className="text-[9px] leading-relaxed text-slate-500">Actions are evaluated before execution. The local preview never performs the requested tool action.</p></div>
          </aside>

          <section className="min-w-0">
            <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
              <div><SectionHeading eyebrow="AUDIT & DECISIONS" title="Governance activity stream" icon={Activity} right={<span className={`flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[8px] tracking-wider ${isOffline ? 'border-orange-300/10 bg-orange-300/[0.04] text-orange-200/80' : 'border-orange-300/10 bg-orange-300/[0.04] text-orange-200/80'}`}><span className={`size-1 rounded-full ${isOffline ? 'bg-orange-300' : 'bg-orange-300'}`} />{isOffline ? 'PREVIEW' : 'LIVE'}</span>} /><p className="-mt-2 ml-11 text-[10px] text-slate-500">Every agent action, evaluated and recorded</p></div>
              <button onClick={refresh} className="flex h-8 items-center gap-1.5 rounded-lg border border-white/[0.07] bg-white/[0.02] px-3 text-[9px] text-slate-400 transition hover:border-white/15 hover:text-slate-200"><RefreshCw className="size-3" />Refresh stream</button>
            </div>
            {isOffline && <div className="mb-3 flex items-center gap-2 rounded-lg border border-orange-200/10 bg-orange-200/[0.03] px-3 py-2 text-[9px] text-orange-100/70"><TriangleAlert className="size-3.5 shrink-0 text-orange-200/80" />Showing sample activity. API requests target <code className="font-mono text-orange-100/90">localhost:5000</code>; check that the service is running and allows browser CORS.</div>}
            <div className="flex flex-col gap-3">
              {events.length ? events.map((event) => <ActivityCard key={event.id} event={event} resolution={resolutions[event.id]} onResolve={resolve} />) : <div className="rounded-xl border border-dashed border-white/[0.08] bg-[#0c1112] px-5 py-12 text-center"><Activity className="mx-auto size-5 text-slate-600" /><p className="mt-3 text-[11px] font-medium text-slate-300">No governance events yet</p><p className="mt-1 text-[10px] text-slate-500">Run an action in the simulator to evaluate the first request.</p></div>}
            </div>
            <div className="mt-4 flex items-center justify-center gap-2 rounded-lg border border-dashed border-white/[0.07] py-3 text-[9px] text-slate-600"><Activity className="size-3" />End of current audit window<span className="text-slate-700">·</span>Polling every 5 seconds</div>
          </section>
        </div>
        <footer className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-white/[0.06] pt-4 text-[9px] text-slate-600"><span className="flex items-center gap-2"><span className="font-semibold tracking-[0.14em] text-slate-500">POLICY FIREWALL</span><span>·</span>Local AI Governance Gatekeeper</span><span className="flex items-center gap-2 font-mono"><span>ENGINE: GEMMA 4</span><span className="text-slate-700">/</span><span>MODE: AIR-GAPPED</span></span></footer>
      </div>
    </main>
  )
}
