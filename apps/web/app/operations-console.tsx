"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  DashboardSummary,
  DeliveryStatus,
  DeliveryView,
  EndpointSummary,
  Provider,
  SimulatorScenario
} from "@hookshield/contracts";
import {
  Activity,
  AlertTriangle,
  Braces,
  Check,
  ChevronDown,
  CircleGauge,
  Clock3,
  Copy,
  Download,
  FileJson,
  Filter,
  KeyRound,
  Menu,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Send,
  Settings2,
  ShieldCheck,
  Webhook,
  X
} from "lucide-react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8787";

interface AuthState {
  user: { id: string; name: string; email: string };
  csrfToken: string;
  demoMode: boolean;
}

const scenarios: Array<{ id: SimulatorScenario; label: string; detail: string }> = [
  { id: "valid", label: "Valid webhook", detail: "Correct signature, fresh timestamp, new delivery ID" },
  { id: "invalid_signature", label: "Incorrect signature", detail: "Signature does not match any usable secret" },
  { id: "tampered_payload", label: "Tampered payload", detail: "Body is changed after signing" },
  { id: "expired_timestamp", label: "Expired timestamp", detail: "Signed timestamp falls outside tolerance" },
  { id: "duplicate", label: "Duplicate delivery", detail: "A valid delivery ID is sent twice" },
  { id: "replay", label: "Replay attempt", detail: "A correctly signed but stale event is reused" },
  { id: "oversized_payload", label: "Oversized payload", detail: "Body exceeds this endpoint's byte policy" },
  { id: "rate_limited", label: "Rate limit exceeded", detail: "Request arrives after the endpoint window is exhausted" },
  { id: "valid_after_rotation", label: "Valid after rotation", detail: "Rotate to a new secret and sign with the active version" }
];

const statusLabels: Record<DeliveryStatus, string> = {
  accepted: "Accepted",
  rejected: "Rejected",
  duplicate: "Duplicate",
  expired: "Expired",
  failed: "Failed"
};

function providerLabel(provider: Provider): string {
  return provider === "generic" ? "Generic HMAC" : provider === "github" ? "GitHub" : "Stripe";
}

function relativeTime(value: string): string {
  const seconds = Math.round((new Date(value).getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  return formatter.format(Math.round(minutes / 60), "hour");
}

function prettyPayload(payload: string): string {
  try {
    return JSON.stringify(JSON.parse(payload), null, 2);
  } catch {
    return payload;
  }
}

export function OperationsConsole() {
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [endpoints, setEndpoints] = useState<EndpointSummary[]>([]);
  const [deliveries, setDeliveries] = useState<DeliveryView[]>([]);
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>("all");
  const [selectedDeliveryId, setSelectedDeliveryId] = useState<string | null>(null);
  const [deliveryDetail, setDeliveryDetail] = useState<DeliveryView | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [statusFilter, setStatusFilter] = useState<DeliveryStatus | "all">("all");
  const [query, setQuery] = useState("");
  const [inspectorTab, setInspectorTab] = useState<"checks" | "payload" | "headers" | "timeline" | "logs">("checks");
  const [dialog, setDialog] = useState<"simulator" | "endpoint" | "rotate" | "settings" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [mobileNav, setMobileNav] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const api = useCallback(async <T,>(path: string, options: RequestInit = {}, token = auth?.csrfToken): Promise<T> => {
    const headers = new Headers(options.headers);
    if (options.body) headers.set("content-type", "application/json");
    if (options.method && options.method !== "GET" && token) headers.set("x-hookshield-csrf", token);
    const response = await fetch(`${API_URL}${path}`, { ...options, headers, credentials: "include" });
    if (!response.ok) {
      const body = await response.json().catch(() => null) as { error?: { message?: string } } | null;
      throw new Error(body?.error?.message ?? `Request failed (${response.status})`);
    }
    if (response.status === 204) return undefined as T;
    return response.json() as Promise<T>;
  }, [auth?.csrfToken]);

  const bootstrap = useCallback(async () => {
    setLoading(true);
    try {
      let session: AuthState;
      try {
        session = await api<AuthState>("/api/auth/me", {}, undefined);
      } catch {
        session = await api<AuthState>("/api/auth/demo", { method: "POST" }, undefined);
      }
      setAuth(session);
      const [endpointData, deliveryData, summaryData] = await Promise.all([
        api<EndpointSummary[]>("/api/endpoints", {}, session.csrfToken),
        api<DeliveryView[]>("/api/deliveries", {}, session.csrfToken),
        api<DashboardSummary>("/api/dashboard", {}, session.csrfToken)
      ]);
      setEndpoints(endpointData);
      setDeliveries(deliveryData);
      setSummary(summaryData);
      setSelectedDeliveryId((current) => current ?? deliveryData[0]?.id ?? null);
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "HookShield could not load.");
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => { void bootstrap(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const refreshDeliveries = useCallback(async () => {
    if (!auth) return;
    const params = new URLSearchParams();
    if (selectedEndpoint !== "all") params.set("endpointId", selectedEndpoint);
    if (statusFilter !== "all") params.set("status", statusFilter);
    if (query.trim()) params.set("query", query.trim());
    const [items, dashboard] = await Promise.all([
      api<DeliveryView[]>(`/api/deliveries?${params}`),
      api<DashboardSummary>("/api/dashboard")
    ]);
    setDeliveries(items);
    setSummary(dashboard);
    if (!items.some((item) => item.id === selectedDeliveryId)) setSelectedDeliveryId(items[0]?.id ?? null);
  }, [api, auth, query, selectedDeliveryId, selectedEndpoint, statusFilter]);

  useEffect(() => {
    if (!auth) return;
    const timer = window.setTimeout(() => { void refreshDeliveries(); }, 180);
    return () => window.clearTimeout(timer);
  }, [auth, selectedEndpoint, statusFilter, query]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selectedDeliveryId || !auth) {
      setDeliveryDetail(null);
      return;
    }
    void api<DeliveryView>(`/api/deliveries/${selectedDeliveryId}`)
      .then(setDeliveryDetail)
      .catch((caught) => setError(caught instanceof Error ? caught.message : "Delivery could not load."));
  }, [api, auth, selectedDeliveryId]);

  const selectedEndpointRecord = useMemo(
    () => endpoints.find((endpoint) => endpoint.id === selectedEndpoint) ?? endpoints[0] ?? null,
    [endpoints, selectedEndpoint]
  );

  async function simulate(endpointId: string, scenario: SimulatorScenario) {
    try {
      const result = await api<{ id: string; status: DeliveryStatus }>("/api/simulator", {
        method: "POST",
        body: JSON.stringify({ endpointId, scenario })
      });
      await refreshDeliveries();
      setSelectedDeliveryId(result.id);
      setDialog(null);
      setNotice(`${statusLabels[result.status]} delivery generated`);
      window.setTimeout(() => setNotice(null), 3000);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The simulation failed.");
    }
  }

  async function retryDelivery() {
    if (!deliveryDetail) return;
    try {
      const updated = await api<DeliveryView>(`/api/deliveries/${deliveryDetail.id}/retry`, { method: "POST" });
      setDeliveryDetail(updated);
      setNotice("Controlled processing retry completed");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Retry was not allowed.");
    }
  }

  function handleListKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (!deliveries.length || !["ArrowDown", "ArrowUp"].includes(event.key)) return;
    event.preventDefault();
    const index = deliveries.findIndex((item) => item.id === selectedDeliveryId);
    const next = event.key === "ArrowDown"
      ? Math.min(index + 1, deliveries.length - 1)
      : Math.max(index - 1, 0);
    setSelectedDeliveryId(deliveries[next]?.id ?? null);
  }

  if (loading) {
    return (
      <main className="app-loading" aria-live="polite">
        <Logo />
        <div className="loading-line" />
        <p>Preparing the security inbox…</p>
      </main>
    );
  }

  if (error && !auth) {
    return (
      <main className="fatal-state">
        <AlertTriangle size={28} />
        <h1>HookShield is not available</h1>
        <p>{error}</p>
        <button className="button primary" onClick={() => void bootstrap()}>Try again</button>
      </main>
    );
  }

  return (
    <main className="shell">
      <aside className={`sidebar ${mobileNav ? "open" : ""}`}>
        <div className="brand-row">
          <Logo />
          <button className="icon-button mobile-only" aria-label="Close navigation" onClick={() => setMobileNav(false)}><X size={18} /></button>
        </div>
        <div className="workspace-label">Operations workspace</div>
        <nav aria-label="Endpoint navigation">
          <button
            className={`nav-item ${selectedEndpoint === "all" ? "active" : ""}`}
            onClick={() => { setSelectedEndpoint("all"); setMobileNav(false); }}
          >
            <Activity size={17} />
            <span>All deliveries</span>
            <strong>{deliveries.length}</strong>
          </button>
          <div className="nav-section-title">
            <span>Endpoints</span>
            <button className="icon-button" aria-label="Create endpoint" onClick={() => setDialog("endpoint")}><Plus size={16} /></button>
          </div>
          {endpoints.map((endpoint) => (
            <button
              key={endpoint.id}
              className={`nav-item endpoint-nav ${selectedEndpoint === endpoint.id ? "active" : ""}`}
              onClick={() => { setSelectedEndpoint(endpoint.id); setMobileNav(false); }}
            >
              <ProviderIcon provider={endpoint.provider} />
              <span><b>{endpoint.name}</b><small>{providerLabel(endpoint.provider)}</small></span>
              <i className={endpoint.enabled ? "online" : "offline"} aria-label={endpoint.enabled ? "Enabled" : "Disabled"} />
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="system-state"><ShieldCheck size={16} /><span><b>Local demo</b><small>SQLite · protected secrets</small></span></div>
          <div className="user-row"><span className="avatar">JM</span><span><b>{auth?.user.name}</b><small>{auth?.user.email}</small></span></div>
        </div>
      </aside>

      <section className="main-column">
        <header className="topbar">
          <button className="icon-button mobile-only" aria-label="Open navigation" onClick={() => setMobileNav(true)}><Menu size={19} /></button>
          <div><span>Operations</span><ChevronDown size={13} /><b>Delivery inbox</b></div>
          <div className="topbar-actions">
            <span className="live-state"><i /> Ingress listening</span>
            <a className="button quiet" href={`${API_URL}/api/audit/export`} target="_blank" rel="noreferrer"><Download size={15} /> Export audit</a>
            <button className="button primary" onClick={() => setDialog("simulator")}><Send size={15} /> Simulate</button>
          </div>
        </header>

        <section className="summary-strip" aria-label="Last 24 hours">
          <Metric label="Deliveries · 24h" value={summary?.total24h ?? 0} detail="All evaluated requests" icon={<Activity size={16} />} />
          <Metric label="Accepted" value={summary?.accepted24h ?? 0} detail={`${summary?.acceptanceRate ?? 0}% acceptance rate`} icon={<Check size={16} />} tone="success" />
          <Metric label="Rejected" value={summary?.rejected24h ?? 0} detail="Stopped by policy" icon={<ShieldCheck size={16} />} tone="danger" />
          <Metric label="Duplicate" value={summary?.duplicate24h ?? 0} detail="Idempotency protected" icon={<RotateCcw size={16} />} tone="warning" />
        </section>

        <section className="toolbar">
          <div className="search-box"><Search size={16} /><input aria-label="Search deliveries" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search event or delivery ID" /></div>
          <label className="select-box"><Filter size={15} /><select aria-label="Filter by status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value as DeliveryStatus | "all")}><option value="all">All states</option>{Object.entries(statusLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          {selectedEndpoint !== "all" && selectedEndpointRecord && <><button className="button quiet" onClick={() => setDialog("settings")}><Settings2 size={15} /> Endpoint settings</button><button className="button quiet" onClick={() => setDialog("rotate")}><KeyRound size={15} /> Rotate secret</button></>}
          <button className="icon-button" aria-label="Refresh deliveries" onClick={() => void refreshDeliveries()}><RefreshCw size={16} /></button>
        </section>

        <section className="workbench">
          <div className="delivery-pane">
            <div className="pane-heading"><div><h1>Deliveries</h1><span>{deliveries.length} matching events</span></div><span className="column-hint">Decision</span></div>
            <div className="delivery-list" ref={listRef} role="listbox" tabIndex={0} aria-label="Webhook deliveries" onKeyDown={handleListKeyDown}>
              {deliveries.length ? deliveries.map((delivery) => (
                <button
                  role="option"
                  aria-selected={selectedDeliveryId === delivery.id}
                  key={delivery.id}
                  className={`delivery-row ${selectedDeliveryId === delivery.id ? "selected" : ""}`}
                  onClick={() => setSelectedDeliveryId(delivery.id)}
                >
                  <StatusMark status={delivery.status} />
                  <span className="delivery-main"><b>{delivery.eventType}</b><small>{delivery.endpointName} · {delivery.providerDeliveryId ?? "No delivery ID"}</small></span>
                  <span className="delivery-meta"><StatusText status={delivery.status} /><time>{relativeTime(delivery.receivedAt)}</time></span>
                </button>
              )) : <EmptyDeliveries onSimulate={() => setDialog("simulator")} />}
            </div>
          </div>

          <aside className="inspector" aria-label="Delivery inspector">
            {deliveryDetail ? (
              <>
                <div className="inspector-heading">
                  <div><span className="eyebrow">Delivery inspector</span><h2>{deliveryDetail.eventType}</h2><code>{deliveryDetail.providerDeliveryId ?? deliveryDetail.id}</code></div>
                  <div className="inspector-heading-actions"><StatusText status={deliveryDetail.status} />{["accepted", "failed"].includes(deliveryDetail.status) && <button className="icon-button" onClick={() => void retryDelivery()} aria-label="Retry controlled processing"><RefreshCw size={15} /></button>}</div>
                </div>
                <dl className="facts"><div><dt>Provider</dt><dd>{providerLabel(deliveryDetail.provider)}</dd></div><div><dt>HTTP</dt><dd>{deliveryDetail.httpStatus}</dd></div><div><dt>Size</dt><dd>{deliveryDetail.payloadBytes.toLocaleString()} B</dd></div><div><dt>Received</dt><dd>{new Date(deliveryDetail.receivedAt).toLocaleTimeString()}</dd></div></dl>
                <div className="tabs" role="tablist">
                  <TabButton id="checks" label="Checks" icon={<ShieldCheck size={15} />} active={inspectorTab} setActive={setInspectorTab} />
                  <TabButton id="payload" label="Payload" icon={<Braces size={15} />} active={inspectorTab} setActive={setInspectorTab} />
                  <TabButton id="headers" label="Headers" icon={<FileJson size={15} />} active={inspectorTab} setActive={setInspectorTab} />
                  <TabButton id="timeline" label="Timeline" icon={<Clock3 size={15} />} active={inspectorTab} setActive={setInspectorTab} />
                  <TabButton id="logs" label="Logs" icon={<Activity size={15} />} active={inspectorTab} setActive={setInspectorTab} />
                </div>
                <div className="inspector-body">
                  {inspectorTab === "checks" && <ChecksPanel delivery={deliveryDetail} />}
                  {inspectorTab === "payload" && <CodePanel value={prettyPayload(deliveryDetail.payload)} label="payload" />}
                  {inspectorTab === "headers" && <HeadersPanel headers={deliveryDetail.headers} />}
                  {inspectorTab === "timeline" && <TimelinePanel delivery={deliveryDetail} />}
                  {inspectorTab === "logs" && <LogsPanel delivery={deliveryDetail} />}
                </div>
              </>
            ) : <div className="inspector-empty"><CircleGauge size={24} /><h2>Select a delivery</h2><p>Inspect the security decision, raw evidence, and processing history.</p></div>}
          </aside>
        </section>
      </section>

      {mobileNav && <button className="scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
      {dialog === "simulator" && <SimulatorDialog endpoints={endpoints} initialEndpoint={selectedEndpointRecord?.id} onClose={() => setDialog(null)} onRun={simulate} />}
      {dialog === "endpoint" && <EndpointDialog api={api} onClose={() => setDialog(null)} onCreated={async () => { setDialog(null); await bootstrap(); setNotice("Endpoint created"); }} />}
      {dialog === "rotate" && selectedEndpointRecord && <RotateDialog endpoint={selectedEndpointRecord} api={api} onClose={() => setDialog(null)} onRotated={async () => { setDialog(null); await bootstrap(); setNotice("Secret rotated; previous version remains in transition"); }} />}
      {dialog === "settings" && selectedEndpointRecord && <EndpointSettingsDialog endpoint={selectedEndpointRecord} api={api} onClose={() => setDialog(null)} onSaved={async (deleted) => { if (deleted) setSelectedEndpoint("all"); setDialog(null); await bootstrap(); setNotice(deleted ? "Endpoint deleted" : "Endpoint policy updated"); }} />}
      {notice && <div className="toast success" role="status"><Check size={16} />{notice}</div>}
      {error && auth && <div className="toast error" role="alert"><AlertTriangle size={16} /><span>{error}</span><button aria-label="Dismiss error" onClick={() => setError(null)}><X size={15} /></button></div>}
    </main>
  );
}

function Logo() {
  return <div className="logo"><span className="logo-mark"><ShieldCheck size={20} /></span><span>Hook<b>Shield</b></span></div>;
}

function ProviderIcon({ provider }: { provider: Provider }) {
  if (provider === "github") return <span className="provider-letter">GH</span>;
  if (provider === "stripe") return <span className="provider-letter">S</span>;
  return <Webhook size={17} />;
}

function Metric({ label, value, detail, icon, tone = "default" }: { label: string; value: number; detail: string; icon: React.ReactNode; tone?: string }) {
  return <div className={`metric ${tone}`}><span className="metric-icon">{icon}</span><div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div></div>;
}

function StatusMark({ status }: { status: DeliveryStatus }) {
  return <span className={`status-mark ${status}`}>{status === "accepted" ? <Check size={14} /> : status === "duplicate" ? <Copy size={13} /> : <X size={13} />}</span>;
}

function StatusText({ status }: { status: DeliveryStatus }) {
  return <span className={`status-text ${status}`}>{statusLabels[status]}</span>;
}

function TabButton({ id, label, icon, active, setActive }: { id: "checks" | "payload" | "headers" | "timeline" | "logs"; label: string; icon: React.ReactNode; active: string; setActive: (id: "checks" | "payload" | "headers" | "timeline" | "logs") => void }) {
  return <button role="tab" aria-selected={active === id} className={active === id ? "active" : ""} onClick={() => setActive(id)}>{icon}{label}</button>;
}

function ChecksPanel({ delivery }: { delivery: DeliveryView }) {
  return <div className="checks-panel"><div className={`decision-banner ${delivery.status}`}><ShieldCheck size={19} /><div><b>{delivery.status === "accepted" ? "Request admitted" : "Request stopped"}</b><span>{delivery.rejectionCode ?? "All enforced checks passed"}</span></div></div><div className="check-list">{delivery.checks.map((check) => <div className="check-row" key={check.id}><span className={`check-icon ${check.status}`}>{check.status === "passed" ? <Check size={13} /> : check.status === "warning" ? <AlertTriangle size={13} /> : <X size={13} />}</span><div><b>{check.name}</b><p>{check.detail}</p></div><span className={`check-word ${check.status}`}>{check.status}</span></div>)}</div></div>;
}

function CodePanel({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return <div className="code-wrap"><button className="copy-code" onClick={() => { void navigator.clipboard.writeText(value); setCopied(true); window.setTimeout(() => setCopied(false), 1500); }}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? "Copied" : `Copy ${label}`}</button><pre><code>{value}</code></pre></div>;
}

function HeadersPanel({ headers }: { headers: Record<string, string> }) {
  return <div className="headers-table">{Object.entries(headers).map(([name, value]) => <div key={name}><code>{name}</code><span className={value === "[REDACTED]" ? "redacted" : ""}>{value}</span></div>)}</div>;
}

function TimelinePanel({ delivery }: { delivery: DeliveryView }) {
  return <div className="timeline"><div><span /><section><b>Received at ingress</b><time>{new Date(delivery.receivedAt).toLocaleString()}</time><p>Raw bytes captured before deserialization.</p></section></div><div><span /><section><b>Security evaluation</b><time>{delivery.processedAt ? new Date(delivery.processedAt).toLocaleString() : "Pending"}</time><p>{delivery.checks.length} policy decisions recorded.</p></section></div>{delivery.timeline.map((entry) => <div key={entry.id}><span /><section><b>Processing attempt {entry.attemptNumber}</b><time>{new Date(entry.startedAt).toLocaleString()}</time><p>{entry.detail}</p></section></div>)}</div>;
}

function LogsPanel({ delivery }: { delivery: DeliveryView }) {
  const lines = [
    { time: delivery.receivedAt, level: "INFO", message: `ingress.received provider=${delivery.provider} bytes=${delivery.payloadBytes}` },
    ...delivery.checks.map((check) => ({
      time: delivery.processedAt ?? delivery.receivedAt,
      level: check.status === "failed" ? "WARN" : "INFO",
      message: `security.check name=${JSON.stringify(check.name)} result=${check.status}`
    })),
    { time: delivery.processedAt ?? delivery.receivedAt, level: delivery.status === "accepted" ? "INFO" : "WARN", message: `security.decision status=${delivery.status} code=${delivery.rejectionCode ?? "none"}` }
  ];
  return <div className="log-view" aria-label="Structured delivery logs">{lines.map((line, index) => <div key={`${line.message}-${index}`}><time>{new Date(line.time).toISOString()}</time><b className={line.level === "WARN" ? "warn" : ""}>{line.level}</b><code>{line.message}</code></div>)}</div>;
}

function EmptyDeliveries({ onSimulate }: { onSimulate: () => void }) {
  return <div className="empty-deliveries"><Webhook size={25} /><h2>No deliveries match</h2><p>Adjust the filters or generate a signed test event.</p><button className="button primary" onClick={onSimulate}>Open simulator</button></div>;
}

function DialogFrame({ title, description, onClose, children }: { title: string; description: string; onClose: () => void; children: React.ReactNode }) {
  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><header><div><h2 id="dialog-title">{title}</h2><p>{description}</p></div><button className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={18} /></button></header>{children}</section></div>;
}

function SimulatorDialog({ endpoints, initialEndpoint, onClose, onRun }: { endpoints: EndpointSummary[]; initialEndpoint?: string; onClose: () => void; onRun: (endpointId: string, scenario: SimulatorScenario) => Promise<void> }) {
  const [endpointId, setEndpointId] = useState(initialEndpoint ?? endpoints[0]?.id ?? "");
  const [scenario, setScenario] = useState<SimulatorScenario>("valid");
  const [running, setRunning] = useState(false);
  const provider = endpoints.find((endpoint) => endpoint.id === endpointId)?.provider;
  return <DialogFrame title="Webhook simulator" description="Generate synthetic events without exposing a port or contacting a provider." onClose={onClose}><div className="dialog-content"><label className="field"><span>Target endpoint</span><select value={endpointId} onChange={(event) => setEndpointId(event.target.value)}>{endpoints.map((endpoint) => <option value={endpoint.id} key={endpoint.id}>{endpoint.name} · {providerLabel(endpoint.provider)}</option>)}</select></label><fieldset className="scenario-list"><legend>Security scenario</legend>{scenarios.map((item) => { const unsupported = provider === "github" && ["expired_timestamp", "replay"].includes(item.id); return <label className={unsupported ? "disabled" : ""} key={item.id}><input type="radio" name="scenario" value={item.id} checked={scenario === item.id} disabled={unsupported} onChange={() => setScenario(item.id)} /><span><b>{item.label}</b><small>{unsupported ? "GitHub does not sign a timestamp" : item.detail}</small></span></label>; })}</fieldset></div><footer><button className="button quiet" onClick={onClose}>Cancel</button><button className="button primary" disabled={!endpointId || running} onClick={async () => { setRunning(true); await onRun(endpointId, scenario); setRunning(false); }}>{running ? <RefreshCw className="spin" size={15} /> : <Send size={15} />}{running ? "Evaluating…" : "Send event"}</button></footer></DialogFrame>;
}

type ApiCall = <T>(path: string, options?: RequestInit) => Promise<T>;

function EndpointDialog({ api, onClose, onCreated }: { api: ApiCall; onClose: () => void; onCreated: () => Promise<void> }) {
  const [name, setName] = useState("");
  const [provider, setProvider] = useState<Provider>("generic");
  const [secret, setSecret] = useState("");
  const [saving, setSaving] = useState(false);
  return <DialogFrame title="Create endpoint" description="The secret is encrypted immediately and never returned by the API." onClose={onClose}><form onSubmit={async (event) => { event.preventDefault(); setSaving(true); await api("/api/endpoints", { method: "POST", body: JSON.stringify({ name, provider, secret, toleranceSeconds: 300, maxPayloadBytes: 262144, rateLimitPerMinute: 60, retentionDays: 14 }) }); await onCreated(); }}><div className="dialog-content form-grid"><label className="field"><span>Endpoint name</span><input autoFocus required minLength={2} maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="Production billing" /></label><label className="field"><span>Provider</span><select value={provider} onChange={(event) => setProvider(event.target.value as Provider)}><option value="generic">Generic HMAC</option><option value="github">GitHub</option><option value="stripe">Stripe</option></select></label><label className="field full"><span>Webhook secret</span><input required minLength={16} maxLength={512} type="password" autoComplete="new-password" value={secret} onChange={(event) => setSecret(event.target.value)} placeholder="Paste a provider secret (16+ characters)" /><small>HookShield has no endpoint that can read this value back.</small></label></div><footer><button type="button" className="button quiet" onClick={onClose}>Cancel</button><button className="button primary" disabled={saving}>{saving ? "Creating…" : "Create endpoint"}</button></footer></form></DialogFrame>;
}

function RotateDialog({ endpoint, api, onClose, onRotated }: { endpoint: EndpointSummary; api: ApiCall; onClose: () => void; onRotated: () => Promise<void> }) {
  const [secret, setSecret] = useState("");
  const [transition, setTransition] = useState(3600);
  return <DialogFrame title="Rotate webhook secret" description={`Create version ${endpoint.secretVersion + 1} for ${endpoint.name}.`} onClose={onClose}><form onSubmit={async (event) => { event.preventDefault(); await api(`/api/endpoints/${endpoint.id}/rotate`, { method: "POST", body: JSON.stringify({ secret, transitionSeconds: transition }) }); await onRotated(); }}><div className="dialog-content form-grid"><label className="field full"><span>New secret</span><input autoFocus required minLength={16} maxLength={512} type="password" autoComplete="new-password" value={secret} onChange={(event) => setSecret(event.target.value)} placeholder="New provider secret" /></label><label className="field full"><span>Transition window</span><select value={transition} onChange={(event) => setTransition(Number(event.target.value))}><option value={0}>No overlap</option><option value={900}>15 minutes</option><option value={3600}>1 hour</option><option value={21600}>6 hours</option></select><small>The previous version is accepted only during this bounded window.</small></label></div><footer><button type="button" className="button quiet" onClick={onClose}>Cancel</button><button className="button primary">Rotate secret</button></footer></form></DialogFrame>;
}

function EndpointSettingsDialog({ endpoint, api, onClose, onSaved }: { endpoint: EndpointSummary; api: ApiCall; onClose: () => void; onSaved: (deleted: boolean) => Promise<void> }) {
  const [name, setName] = useState(endpoint.name);
  const [enabled, setEnabled] = useState(endpoint.enabled);
  const [tolerance, setTolerance] = useState(endpoint.toleranceSeconds);
  const [maxPayload, setMaxPayload] = useState(endpoint.maxPayloadBytes);
  const [rateLimit, setRateLimit] = useState(endpoint.rateLimitPerMinute);
  const [retention, setRetention] = useState(endpoint.retentionDays);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  async function savePolicy() {
    setSaving(true);
    setFormError(null);
    try {
      await api(`/api/endpoints/${endpoint.id}`, { method: "PATCH", body: JSON.stringify({ name, enabled, toleranceSeconds: tolerance, maxPayloadBytes: maxPayload, rateLimitPerMinute: rateLimit, retentionDays: retention }) });
      await onSaved(false);
    } catch (caught) {
      setFormError(caught instanceof Error ? caught.message : "Endpoint policy could not be saved.");
      setSaving(false);
    }
  }
  return <DialogFrame title="Endpoint settings" description={`Edit ingress policy for ${providerLabel(endpoint.provider)}. Secrets are managed separately.`} onClose={onClose}><form onSubmit={(event) => { event.preventDefault(); void savePolicy(); }}><div className="dialog-content form-grid"><label className="field full"><span>Endpoint name</span><input required minLength={2} maxLength={80} value={name} onChange={(event) => setName(event.target.value)} /></label><label className="toggle-field full"><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} /><span><b>Accept deliveries</b><small>Disabled endpoints return the same public not-found response.</small></span></label><label className="field"><span>Freshness tolerance</span><input type="number" min={30} max={900} value={tolerance} onChange={(event) => setTolerance(Number(event.target.value))} /></label><label className="field"><span>Max payload bytes</span><input type="number" min={1024} max={1048576} value={maxPayload} onChange={(event) => setMaxPayload(Number(event.target.value))} /></label><label className="field"><span>Requests per minute</span><input type="number" min={1} max={600} value={rateLimit} onChange={(event) => setRateLimit(Number(event.target.value))} /></label><label className="field"><span>Retention days</span><input type="number" min={1} max={90} value={retention} onChange={(event) => setRetention(Number(event.target.value))} /></label><div className="danger-zone full"><div><b>Delete endpoint</b><small>Removes its deliveries, checks, attempts, and encrypted secret versions.</small></div>{confirmDelete ? <div className="confirm-delete"><span>Delete permanently?</span><button type="button" className="button danger" onClick={async () => { await api(`/api/endpoints/${endpoint.id}`, { method: "DELETE" }); await onSaved(true); }}>Confirm delete</button><button type="button" className="button quiet" onClick={() => setConfirmDelete(false)}>Keep endpoint</button></div> : <button type="button" className="button danger-outline" onClick={() => setConfirmDelete(true)}>Delete endpoint</button>}</div>{formError && <div className="form-error full" role="alert">{formError}</div>}</div><footer><button type="button" className="button quiet" onClick={onClose}>Cancel</button><button type="button" className="button primary" disabled={saving} onClick={() => void savePolicy()}>{saving ? "Saving…" : "Save policy"}</button></footer></form></DialogFrame>;
}
