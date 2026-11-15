
import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Cloud,
  Database,
  FileBarChart2,
  Gauge,
  GitBranch,
  Layers3,
  LoaderCircle,
  Network,
  Play,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Trash2,
  Zap,
} from "lucide-react";
import {
  apiRequest,
  checkBackend,
  downloadApiFile,
  endpoints,
} from "./api";

const NAV_ITEMS = [
  { id: "overview", label: "Overview", group: "Workspace", icon: Gauge },
  { id: "attacks", label: "Attack Simulation", group: "Security", icon: ShieldAlert },
  { id: "detection", label: "Traffic Detection", group: "Security", icon: BrainCircuit },
  { id: "placement", label: "Cache Placement", group: "Optimization", icon: Layers3 },
  { id: "recovery", label: "Adaptive Recovery", group: "Operations", icon: RefreshCw },
  { id: "experiments", label: "Experiments", group: "Operations", icon: FileBarChart2 },
];

const NAV_GROUPS = ["Workspace", "Security", "Optimization", "Operations"];

const SCENARIOS = [
  {
    value: "cache_pollution",
    label: "Cache Pollution",
    description: "Unique-content requests intended to pollute edge caches.",
  },
  {
    value: "distributed_low_rate",
    label: "Distributed Low-Rate Pollution",
    description: "A mixture of shared content and low-rate attack requests.",
  },
  {
    value: "flash_crowd",
    label: "Legitimate Flash Crowd",
    description: "A surge of requests for the same popular content.",
  },
];

const INITIAL_ATTACK = {
  scenario: "cache_pollution",
  edge_id: "edge-hyd",
  request_count: 200,
  seed: 42,
};

const INITIAL_RECOVERY = {
  edge_id: "",
  max_events: 100000,
  min_content_requests: 2,
  attack_ratio_threshold: 0.5,
  min_trust_ratio: 0.6,
  max_evictions_per_edge: 20,
  max_replications_per_edge: 10,
  coordinate_edges: true,
  apply_recovery: false,
};

const INITIAL_PLACEMENT = {
  edge_id: "",
  prediction_limit: 100,
  max_events: 100000,
  window_size: 50,
  uncertainty_penalty: 1,
  apply_placement: false,
};

const INITIAL_SYSTEM = {
  edge_id: "edge-hyd",
  content_id: "edgeguard-demo-content",
  response_size_bytes: 131072,
  dataset: "synthetic",
  dataset_limit: 200,
  strategy: "LRU",
};

function formatNumber(value, digits = 0) {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  if (!Number.isFinite(number)) return String(value);
  return number.toLocaleString(undefined, {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  });
}

function formatPercent(value) {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return `${formatNumber(number * 100, 1)}%`;
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${formatNumber(bytes)} B`;
  if (bytes < 1024 ** 2) return `${formatNumber(bytes / 1024, 1)} KB`;
  if (bytes < 1024 ** 3) return `${formatNumber(bytes / 1024 ** 2, 2)} MB`;
  return `${formatNumber(bytes / 1024 ** 3, 2)} GB`;
}

function getErrorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function formatLabel(value) {
  return String(value)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^./, (character) => character.toUpperCase());
}

function formatResultValue(value, key = "") {
  if (value === null || value === undefined || value === "") return "Unavailable";
  if (typeof value === "boolean") return value ? "Yes" : "No";

  if (typeof value === "number") {
    if (/(?:^|_)(?:bytes|size_bytes|capacity_bytes)$|bytes_transferred$/.test(key)) {
      return formatBytes(value);
    }
    if (key.endsWith("_percent")) return `${formatNumber(value, 1)}%`;
    if (/(?:ratio|accuracy|confidence)$/.test(key)) return formatPercent(value);
    if (key.endsWith("_ms")) return `${formatNumber(value, 2)} ms`;
    return formatNumber(value, Number.isInteger(value) ? 0 : 3);
  }

  if (typeof value === "string") {
    return /^(classification|scenario|status|mode|demand_status)$/.test(key)
      ? formatLabel(value)
      : value;
  }

  return null;
}

function CompactValue({ value, field = "" }) {
  const displayValue = formatResultValue(value, field);
  if (displayValue !== null) {
    if (typeof value === "boolean") {
      return (
        <StatusPill status={value ? "good" : "neutral"}>
          {displayValue}
        </StatusPill>
      );
    }
    return <span className="break-words text-slate-200">{displayValue}</span>;
  }

  if (Array.isArray(value)) {
    if (!value.length) return <span className="text-slate-500">None</span>;
    if (value.every((item) => item === null || ["string", "number", "boolean"].includes(typeof item))) {
      return (
        <span className="break-words text-slate-300">
          {value.map((item) => formatResultValue(item, field)).join(", ")}
        </span>
      );
    }
    return <span className="text-slate-300">{formatNumber(value.length)} records</span>;
  }

  if (typeof value === "object") {
    return (
      <span className="break-words text-slate-300">
        {Object.entries(value)
          .map(([key, item]) => `${formatLabel(key)}: ${formatResultValue(item, key) ?? "Details available"}`)
          .join(" · ")}
      </span>
    );
  }

  return <span className="text-slate-500">Unavailable</span>;
}

function RecordTable({ rows, title, emptyMessage }) {
  const columns = [...new Set(rows.flatMap((row) => Object.keys(row || {})))];

  if (!rows.length) {
    return (
      <div className="rounded-lg border border-dashed border-slate-700 px-4 py-6 text-center text-xs text-slate-500">
        {emptyMessage || `No ${title.toLowerCase()} returned.`}
      </div>
    );
  }

  if (!columns.length) {
    return (
      <div className="rounded-lg border border-slate-800 bg-[#0b111c] p-3 text-xs text-slate-300">
        {rows.map((value) => formatResultValue(value, title.toLowerCase())).join(", ")}
      </div>
    );
  }

  return (
    <div className="data-scroll max-h-[420px] rounded-lg border border-slate-800">
      <table className="w-full min-w-max text-left text-xs">
        <thead className="sticky top-0 bg-[#0b111c] text-slate-400">
          <tr>
            {columns.map((column) => (
              <th key={column} className="whitespace-nowrap px-3 py-2.5 font-medium">
                {formatLabel(column)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr key={row.id ?? row.request_id ?? `${title}-${rowIndex}`} className="border-t border-slate-800">
              {columns.map((column) => (
                <td key={column} className="max-w-xs px-3 py-2.5 align-top text-slate-300">
                  <CompactValue value={row?.[column]} field={column} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function StructuredResult({ data, emptyMessage }) {
  if (Array.isArray(data)) {
    return <RecordTable rows={data} title="Records" />;
  }

  if (!data || typeof data !== "object") {
    return <CompactValue value={data} />;
  }

  const entries = Object.entries(data);
  const summaryEntries = entries.filter(
    ([key, value]) => key !== "message" && (value === null || typeof value !== "object")
  );
  const detailEntries = entries.filter(([, value]) => value !== null && typeof value === "object");

  return (
    <div className="space-y-4">
      {typeof data.message === "string" && (
        <p className="rounded-lg border border-indigo-400/15 bg-indigo-400/5 px-3 py-2.5 text-sm leading-6 text-indigo-100">
          {data.message}
        </p>
      )}
      {summaryEntries.length > 0 && (
        <dl className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {summaryEntries.map(([key, value]) => (
            <div key={key} className="min-w-0 rounded-lg border border-slate-800 bg-[#0b111c] p-3">
              <dt className="text-[11px] text-slate-500">{formatLabel(key)}</dt>
              <dd className="mt-1.5 break-words text-sm font-medium">
                <CompactValue value={value} field={key} />
              </dd>
            </div>
          ))}
        </dl>
      )}
      {detailEntries.map(([key, value]) => (
        <section key={key} className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            {formatLabel(key)}
            {Array.isArray(value) && (
              <span className="ml-2 font-normal normal-case tracking-normal text-slate-500">
                {formatNumber(value.length)} records
              </span>
            )}
          </h4>
          {Array.isArray(value) ? (
            <RecordTable
              rows={value}
              title={emptyMessage && key === "runs" ? "recovery runs" : formatLabel(key)}
              emptyMessage={emptyMessage && key === "runs" ? emptyMessage : undefined}
            />
          ) : (
            <StructuredResult data={value} />
          )}
        </section>
      ))}
      {entries.length === 0 && (
        <p className="py-8 text-center text-sm text-slate-500">
          {emptyMessage || "No response fields were returned."}
        </p>
      )}
    </div>
  );
}

function MetricCard({ title, value, subtitle, icon: Icon, accent = "indigo" }) {
  const accents = {
    indigo: "text-indigo-300 bg-indigo-400/10",
    cyan: "text-cyan-300 bg-cyan-400/10",
    emerald: "text-emerald-300 bg-emerald-400/10",
    amber: "text-amber-300 bg-amber-400/10",
    rose: "text-rose-300 bg-rose-400/10",
    violet: "text-violet-300 bg-violet-400/10",
  };

  return (
    <div className="panel p-4 sm:p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs text-slate-400">{title}</p>
          <p className="mt-3 break-words text-2xl font-semibold tracking-tight text-white">
            {value}
          </p>
          <p className="mt-2 text-xs text-slate-500">{subtitle}</p>
        </div>
        <div className={`rounded-xl p-2.5 ${accents[accent] || accents.indigo}`}>
          <Icon size={19} />
        </div>
      </div>
    </div>
  );
}

function SectionHeading({ eyebrow, title, description, icon: Icon }) {
  return (
    <div className="mb-6">
      <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-indigo-300">
        {Icon && <Icon size={15} />}
        {eyebrow}
      </div>
      <h2 className="text-2xl font-semibold tracking-tight text-white">{title}</h2>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
        {description}
      </p>
    </div>
  );
}

function StatusPill({ children, status = "neutral" }) {
  const styles = {
    good: "border-emerald-400/20 bg-emerald-400/10 text-emerald-300",
    bad: "border-rose-400/20 bg-rose-400/10 text-rose-300",
    warning: "border-amber-400/20 bg-amber-400/10 text-amber-300",
    neutral: "border-slate-600/40 bg-slate-700/20 text-slate-300",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${styles[status] || styles.neutral
        }`}
    >
      <CircleDot size={10} />
      {children}
    </span>
  );
}

function ResultPanel({ title, data, error, loading, emptyMessage }) {
  const isEmpty = Boolean(
    emptyMessage &&
    Array.isArray(data?.runs) &&
    data.runs.length === 0
  );

  return (
    <section className="panel min-w-0 overflow-hidden">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
          <Terminal size={15} className="text-indigo-300" />
          {title}
        </div>
        {loading && (
          <LoaderCircle className="animate-spin text-indigo-300" size={16} />
        )}
        {!loading && error && <StatusPill status="bad">Failed</StatusPill>}
        {!loading && !error && data && (
          <StatusPill status={isEmpty ? "neutral" : "good"}>
            {isEmpty ? "Empty" : "Received"}
          </StatusPill>
        )}
      </div>
      <div className="p-4">
        {loading ? (
          <div className="flex min-h-36 items-center justify-center gap-2 text-sm text-slate-400">
            <LoaderCircle className="animate-spin" size={18} />
            Waiting for backend response…
          </div>
        ) : error ? (
          <div className="rounded-lg border border-rose-400/20 bg-rose-400/5 p-3 text-sm leading-6 text-rose-200">
            {error}
          </div>
        ) : data ? (
          <div className="space-y-4">
            <StructuredResult data={data} emptyMessage={emptyMessage} />
            <details className="group border-t border-slate-800 pt-3">
              <summary className="cursor-pointer text-xs font-medium text-slate-400 hover:text-slate-200">
                Technical Details
              </summary>
              <pre className="mt-3 max-h-[440px] overflow-auto rounded-lg bg-[#090e17] p-3 text-xs leading-5 text-slate-300">
                {JSON.stringify(data, null, 2)}
              </pre>
            </details>
          </div>
        ) : (
          <div className="flex min-h-36 items-center justify-center text-sm text-slate-500">
            Run an operation to view its response here.
          </div>
        )}
      </div>
    </section>
  );
}

function Field({ label, children, hint }) {
  return (
    <label className="block min-w-0">
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1.5 block text-[11px] text-slate-500">{hint}</span>}
    </label>
  );
}

function Toggle({ label, checked, onChange, description }) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-slate-800 bg-[#0b111c] p-3">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-1 accent-indigo-500"
      />
      <span>
        <span className="block text-sm text-slate-200">{label}</span>
        {description && (
          <span className="mt-1 block text-xs leading-5 text-slate-500">
            {description}
          </span>
        )}
      </span>
    </label>
  );
}

const NETWORK_PATHS = {
  "edge-hyd": "M 500 104 C 500 158 166 158 166 234",
  "edge-mum": "M 500 104 C 500 154 500 174 500 234",
  "edge-del": "M 500 104 C 500 158 834 158 834 234",
};

function NetworkSimulation({
  topology,
  stats,
  events = [],
  error,
  flow,
  online,
  busy,
  showControls = true,
  selectedEdgeId,
  onEdgeChange,
  onSendRequest,
  onRunScenario,
}) {
  const edges = Array.isArray(topology?.edges) ? topology.edges : [];
  const origin = topology?.origin;
  const edgeStats = (edge) => edge.cache || {};

  return (
    <section className="network-panel">
      <div className="network-panel-heading">
        <div>
          <div className="network-kicker">
            <span className="network-live-dot" />
            SIMULATED CDN FABRIC
          </div>
          <h3 className="mt-2 text-lg font-semibold text-white">Request flow</h3>
          <p className="mt-1 text-xs text-slate-400">
            Traffic moves through edge caches. Cyan highlights requests; rose highlights attack scenarios.
          </p>
        </div>
        <span className={`network-status ${online ? "is-online" : "is-offline"}`}>
          <span />
          {online ? "SIMULATOR CONNECTED" : "BACKEND OFFLINE"}
        </span>
      </div>

      <div className="network-content">
        <div className="network-stage" aria-label="CDN origin connected to edge caches">
          <svg
            className="network-connectors"
            viewBox="0 0 1000 360"
            preserveAspectRatio="none"
            aria-hidden="true"
          >
            {Object.entries(NETWORK_PATHS).map(([edgeId, path]) => (
              <path
                key={edgeId}
                d={path}
                className={`network-link ${flow?.edgeId === edgeId ? "is-active" : ""} ${
                  flow?.edgeId === edgeId && flow.type === "attack"
                    ? "is-attack"
                    : ""
                }`}
              />
            ))}
            {flow && NETWORK_PATHS[flow.edgeId] && (
              <circle
                key={flow.id}
                r="5"
                className={`network-packet ${flow.type === "attack" ? "is-attack" : ""}`}
              >
                <animateMotion
                  path={NETWORK_PATHS[flow.edgeId]}
                  dur="1.35s"
                  fill="freeze"
                />
              </circle>
            )}
          </svg>

          <div className="network-origin">
            <div className="network-node-icon origin-icon"><Database size={19} /></div>
            <div className="min-w-0">
              <p className="network-node-label">ORIGIN</p>
              <p className="truncate text-sm font-semibold text-white">
                {origin?.name || "Central Origin Server"}
              </p>
              <p className="mt-1 text-[11px] text-slate-400">
                {origin?.location || "Waiting for simulator"}
                {origin?.processing_latency_ms != null
                  ? ` · ${formatNumber(origin.processing_latency_ms, 1)} ms`
                  : ""}
              </p>
            </div>
            <span className="origin-bandwidth">
              {origin?.bandwidth_mbps != null
                ? `${formatNumber(origin.bandwidth_mbps)} Mbps`
                : "ORIGIN"}
            </span>
          </div>

          <div className="network-edge-grid">
            {edges.map((edge) => {
              const cache = edgeStats(edge);
              const utilization = Math.max(
                0,
                Math.min(100, Number(cache.utilization_percent) || 0)
              );
              const edgeFlow = flow?.edgeId === edge.id;

              return (
                <article
                  key={edge.id}
                  className={`network-edge ${edgeFlow ? "is-flowing" : ""} ${
                    edgeFlow && flow.type === "attack" ? "is-attack" : ""
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2.5">
                      <div className="network-node-icon edge-icon"><Server size={17} /></div>
                      <div className="min-w-0">
                        <p className="truncate text-xs font-semibold text-white">
                          {edge.name || edge.id}
                        </p>
                        <p className="mt-0.5 truncate text-[10px] text-slate-500">
                          {edge.location || edge.id}
                        </p>
                      </div>
                    </div>
                    <span className={`network-edge-state ${edgeFlow ? "is-flowing" : ""} ${
                      edgeFlow && flow.type === "attack" ? "is-attack" : ""
                    }`}>
                      {edgeFlow
                        ? flow.type === "attack" ? "ATTACK" : "FLOW"
                        : "EDGE"}
                    </span>
                  </div>
                  <div className="mt-4 flex items-center justify-between text-[10px]">
                    <span className="text-slate-400">CACHE UTILIZATION</span>
                    <span className="font-mono text-cyan-200">
                      {formatNumber(utilization, 1)}%
                    </span>
                  </div>
                  <div
                    className="network-cache-track"
                    role="progressbar"
                    aria-label={`${edge.location || edge.id} cache utilization`}
                    aria-valuenow={utilization}
                    aria-valuemin={0}
                    aria-valuemax={100}
                  >
                    <span style={{ width: `${utilization}%` }} />
                  </div>
                  <div className="mt-2 flex justify-between text-[10px] text-slate-500">
                    <span>
                      {formatBytes(cache.used_bytes || 0)} / {formatBytes(cache.capacity_bytes || 0)}
                    </span>
                    <span>{cache.strategy || "LRU"}</span>
                  </div>
                </article>
              );
            })}
            {!edges.length && (
              <div className="network-empty">
                {error || "Start the backend to load the simulated edge nodes."}
              </div>
            )}
          </div>
        </div>

        <aside className="network-console">
          <div className="network-console-top">
            <span className="network-kicker">LIVE SIMULATION</span>
            <span className="network-console-icon"><Activity size={17} /></span>
          </div>
          <div className="network-total">
            <span>{formatNumber(stats?.requests || 0)}</span>
            <small>requests processed</small>
          </div>
          <div className="network-stat-grid">
            <div>
              <span>HIT RATIO</span>
              <strong>{formatPercent(stats?.cache_hit_ratio)}</strong>
            </div>
            <div>
              <span>ORIGIN CALLS</span>
              <strong>{formatNumber(stats?.origin_requests || 0)}</strong>
            </div>
            <div>
              <span>AVG LATENCY</span>
              <strong>{formatNumber(stats?.average_latency_ms || 0, 2)} ms</strong>
            </div>
            <div>
              <span>ORIGIN DATA</span>
              <strong>{formatBytes(stats?.origin_bytes_transferred || 0)}</strong>
            </div>
          </div>
          <div className="network-flow-status">
            <span className={`network-live-dot ${flow ? "is-active" : ""}`} />
            {flow
              ? flow.type === "attack"
                ? `Attack traffic targeting ${flow.edgeId}`
                : `Request flowing to ${flow.edgeId}`
              : "Network ready for requests"}
          </div>
          {error && edges.length > 0 && (
            <p className="mt-2 text-[10px] leading-4 text-rose-300">{error}</p>
          )}
          {showControls && (
            <>
              <label className="network-edge-selector">
                Route requests and attacks to
                <select
                  aria-label="Route requests and attacks to"
                  value={selectedEdgeId}
                  onChange={(event) => onEdgeChange(event.target.value)}
                  disabled={!online || busy || edges.length === 0}
                >
                  {edges.map((edge) => (
                    <option key={edge.id} value={edge.id}>
                      {edge.name || edge.location || edge.id}
                    </option>
                  ))}
                </select>
              </label>
              <div className="network-actions">
                <button
                  type="button"
                  className="network-action-primary"
                  onClick={onSendRequest}
                  disabled={!online || busy}
                >
                  {busy ? <LoaderCircle className="animate-spin" size={15} /> : <Play size={15} />}
                  Send test request
                </button>
                <button
                  type="button"
                  className="network-action-secondary"
                  onClick={onRunScenario}
                  disabled={!online || busy}
                >
                  <ShieldAlert size={15} />
                  Run attack scenario
                </button>
              </div>
            </>
          )}
        </aside>
      </div>

      <div className="network-timeline">
        <div className="network-timeline-heading">
          <div>
            <p className="network-kicker">REQUEST TRACE</p>
            <h4 className="mt-1 text-sm font-semibold text-slate-200">Latest network events</h4>
          </div>
          <span className="text-[10px] text-slate-500">
            {formatNumber(events.length)} recent
          </span>
        </div>
        {events.length ? (
          <div className="network-event-list">
            {[...events].reverse().map((event, index) => (
              <div
                key={`${event.edge_id}-${event.content_id}-${event.timestamp}-${index}`}
                className="network-event"
              >
                <span className={`network-event-result ${event.cache_hit ? "is-hit" : "is-miss"}`}>
                  {event.cache_hit ? <Zap size={12} /> : <Cloud size={12} />}
                  {event.cache_hit ? "HIT" : "MISS"}
                </span>
                <span className="network-event-content" title={event.content_id}>
                  {event.content_id || "Unknown content"}
                </span>
                <span className="network-event-edge">{event.edge_id}</span>
                <span className="network-event-route">
                  {event.cache_hit ? "edge cache" : "origin"}
                </span>
                <span className="network-event-latency">
                  {formatNumber(event.total_latency_ms, 2)} ms
                </span>
                <span className="network-event-time">
                  {event.recorded_at
                    ? new Date(event.recorded_at).toLocaleTimeString()
                    : "—"}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="network-timeline-empty">
            No requests recorded yet. Send a test request or replay a dataset to populate the trace.
          </p>
        )}
      </div>
    </section>
  );
}

function App() {
  const [activePage, setActivePage] = useState("overview");
  const [backendStatus, setBackendStatus] = useState("checking");
  const [backendError, setBackendError] = useState("");
  const [networkTopology, setNetworkTopology] = useState(null);
  const [networkStats, setNetworkStats] = useState(null);
  const [networkEvents, setNetworkEvents] = useState([]);
  const [networkError, setNetworkError] = useState("");
  const [networkFlow, setNetworkFlow] = useState(null);
  const flowTimeoutRef = useRef(null);
  const [savedExperimentHistory, setSavedExperimentHistory] = useState(null);
  const [savedHistoryError, setSavedHistoryError] = useState("");

  const [attackForm, setAttackForm] = useState(INITIAL_ATTACK);
  const [recoveryForm, setRecoveryForm] = useState(INITIAL_RECOVERY);
  const [placementForm, setPlacementForm] = useState(INITIAL_PLACEMENT);
  const [systemForm, setSystemForm] = useState(INITIAL_SYSTEM);

  const [loadingAction, setLoadingAction] = useState("");
  const [results, setResults] = useState({});
  const [errors, setErrors] = useState({});
  const [experimentLog, setExperimentLog] = useState([]);

  const updateTargetEdge = (edgeId) => {
    setSystemForm((previous) => ({ ...previous, edge_id: edgeId }));
    setAttackForm((previous) => ({ ...previous, edge_id: edgeId }));
  };

  const [latestAttack, setLatestAttack] = useState(null);
  const [latestDiscrimination, setLatestDiscrimination] = useState(null);
  const [latestTrustedDemand, setLatestTrustedDemand] = useState(null);
  const [latestRecovery, setLatestRecovery] = useState(null);
  const [latestEvaluation, setLatestEvaluation] = useState(null);
  const [history, setHistory] = useState(null);

  const refreshBackend = useCallback(async () => {
    try {
      await checkBackend();
      setBackendStatus("online");
      setBackendError("");
    } catch (error) {
      setBackendStatus("offline");
      setBackendError(getErrorMessage(error));
    }
  }, []);

  const refreshNetworkState = useCallback(async () => {
    try {
      const [topology, stats, eventResponse] = await Promise.all([
        apiRequest(endpoints.networkTopology),
        apiRequest(endpoints.networkStats),
        apiRequest(endpoints.recentEvents),
      ]);
      setNetworkTopology(topology);
      setNetworkStats(stats);
      setNetworkEvents(eventResponse?.events || []);
      setNetworkError("");
    } catch (error) {
      setNetworkError(getErrorMessage(error));
    }
  }, []);

  const refreshExperimentHistory = useCallback(async () => {
    try {
      const response = await apiRequest(endpoints.experimentHistory);
      setSavedExperimentHistory(response);
      setSavedHistoryError("");
    } catch (error) {
      setSavedHistoryError(getErrorMessage(error));
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(refreshBackend, 0);
    return () => window.clearTimeout(timer);
  }, [refreshBackend]);

  useEffect(() => {
    if (
      backendStatus !== "online" ||
      !["overview", "attacks"].includes(activePage)
    ) {
      return undefined;
    }
    const initialRefresh = window.setTimeout(refreshNetworkState, 0);
    const timer = window.setInterval(refreshNetworkState, 3000);
    return () => {
      window.clearTimeout(initialRefresh);
      window.clearInterval(timer);
    };
  }, [activePage, backendStatus, refreshNetworkState]);

  useEffect(() => {
    if (backendStatus === "online" && activePage === "experiments") {
      const timer = window.setTimeout(refreshExperimentHistory, 0);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [activePage, backendStatus, refreshExperimentHistory]);

  useEffect(() => () => window.clearTimeout(flowTimeoutRef.current), []);

  const animateNetworkFlow = useCallback((edgeId, type = "request") => {
    window.clearTimeout(flowTimeoutRef.current);
    setNetworkFlow({ edgeId, type, id: Date.now() });
    flowTimeoutRef.current = window.setTimeout(() => setNetworkFlow(null), 1500);
  }, []);

  const recordResult = useCallback((key, data) => {
    setResults((previous) => ({ ...previous, [key]: data }));
    setErrors((previous) => ({ ...previous, [key]: "" }));
    if (["attack", "simulateRequest", "datasetReplay", "resetNetwork"].includes(key)) {
      refreshNetworkState();
    }
    if (
      [
        "attack",
        "simulateRequest",
        "datasetReplay",
        "demandEvaluation",
        "anomalyEvaluation",
      ].includes(key)
    ) {
      refreshExperimentHistory();
    }

    const entry = {
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      timestamp: new Date().toLocaleTimeString(),
      operation: key,
      success: true,
      data,
    };
    setExperimentLog((previous) => [entry, ...previous].slice(0, 100));
  }, [refreshExperimentHistory, refreshNetworkState]);

  const runAction = useCallback(
    async (key, path, body, onSuccess, method = "POST") => {
      setLoadingAction(key);
      setErrors((previous) => ({ ...previous, [key]: "" }));

      try {
        const options = {
          method,
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        };

        const data = await apiRequest(path, options);
        recordResult(key, data);
        onSuccess?.(data);
        return data;
      } catch (error) {
        const message = getErrorMessage(error);
        setErrors((previous) => ({ ...previous, [key]: message }));
        setExperimentLog((previous) => [
          {
            id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
            timestamp: new Date().toLocaleTimeString(),
            operation: key,
            success: false,
            error: message,
          },
          ...previous,
        ].slice(0, 100));
        return null;
      } finally {
        setLoadingAction("");
      }
    },
    [recordResult]
  );

  const runAttack = () => {
    animateNetworkFlow(attackForm.edge_id, "attack");
    return runAction("attack", endpoints.attackSimulation, {
      scenario: attackForm.scenario,
      edge_id: attackForm.edge_id,
      request_count: Number(attackForm.request_count),
      seed: Number(attackForm.seed),
    }, setLatestAttack);
  };

  const runManualRequest = () => {
    animateNetworkFlow(systemForm.edge_id);
    return runAction("simulateRequest", endpoints.simulateRequest, {
      edge_id: systemForm.edge_id,
      content_id: systemForm.content_id,
      response_size_bytes: Number(systemForm.response_size_bytes),
    });
  };

  const runDemandPredictions = () =>
    runAction(
      "demandPredictions",
      `${endpoints.demandPredictions}?limit=100${
        recoveryForm.edge_id
          ? `&edge_id=${encodeURIComponent(recoveryForm.edge_id)}`
          : ""
      }`,
      undefined,
      undefined,
      "GET"
    );

  const runDatasetReplay = () => {
    animateNetworkFlow(systemForm.edge_id);
    return runAction("datasetReplay", endpoints.replayDataset, {
      dataset: systemForm.dataset,
      edge_id: systemForm.edge_id,
      limit: Number(systemForm.dataset_limit),
    });
  };

  const runCacheStrategy = () =>
    runAction(
      "cacheStrategy",
      endpoints.cacheStrategy(systemForm.edge_id),
      { strategy: systemForm.strategy },
      undefined,
      "PUT"
    );

  const loadCacheStats = () =>
    runAction("cacheStats", endpoints.cacheStats, undefined, undefined, "GET");

  const loadMetrics = () =>
    runAction("metrics", endpoints.metrics, undefined, undefined, "GET");

  const resetBackend = () => {
    if (window.confirm("Reset all CDN caches, metrics, and trained AI models?")) {
      runAction("resetNetwork", endpoints.resetNetwork, undefined);
    }
  };

  const runDemandTraining = () =>
    runAction("demandTraining", endpoints.trainDemand, {
      window_size: 25,
      max_events: Number(recoveryForm.max_events),
    });

  const runDemandEvaluation = () =>
    runAction("demandEvaluation", endpoints.evaluateDemand, {
      window_size: 25,
      max_events: Number(recoveryForm.max_events),
      train_ratio: 0.8,
    });

  const runAnomalyTraining = () =>
    runAction("anomalyTraining", endpoints.trainAnomaly, {
      window_size: 10,
      max_events: Number(recoveryForm.max_events),
    });

  const runAnomalyEvaluation = () =>
    runAction("anomalyEvaluation", endpoints.evaluateAnomaly, {
      window_size: 25,
      max_events: Number(recoveryForm.max_events),
      train_ratio: 0.8,
      attack_ratio_threshold: 0.01,
    });

  const runAnomalyAnalysis = () =>
    runAction(
      "anomalyAnalysis",
      `${endpoints.analyzeAnomaly}${recoveryForm.edge_id
        ? `?edge_id=${encodeURIComponent(recoveryForm.edge_id)}`
        : ""}`,
      undefined,
      undefined,
      "GET"
    );

  const runDiscrimination = () =>
    runAction("discrimination", endpoints.discriminationAnalyze, {
      edge_id: recoveryForm.edge_id || null,
      window_size: 50,
      max_events: Number(recoveryForm.max_events),
    }, setLatestDiscrimination);

  const runEvaluation = () =>
    runAction("evaluation", endpoints.discriminationEvaluate, {
      edge_id: recoveryForm.edge_id || null,
      window_size: 50,
      max_events: Number(recoveryForm.max_events),
    }, setLatestEvaluation);

  const runTrustedDemand = () =>
    runAction("trustedDemand", endpoints.trustedDemand, {
      edge_id: recoveryForm.edge_id || null,
      window_size: 50,
      max_events: Number(recoveryForm.max_events),
    }, setLatestTrustedDemand);

  const runPlacement = () =>
    runAction("placement", endpoints.placement, {
      edge_id: placementForm.edge_id || null,
      prediction_limit: Number(placementForm.prediction_limit),
      max_events: Number(placementForm.max_events),
      window_size: Number(placementForm.window_size),
      uncertainty_penalty: Number(placementForm.uncertainty_penalty),
      apply_placement: Boolean(placementForm.apply_placement),
    });

  const runRecovery = () =>
    runAction("recovery", endpoints.recovery, {
      ...recoveryForm,
      edge_id: recoveryForm.edge_id || null,
      max_events: Number(recoveryForm.max_events),
      min_content_requests: Number(recoveryForm.min_content_requests),
      attack_ratio_threshold: Number(recoveryForm.attack_ratio_threshold),
      min_trust_ratio: Number(recoveryForm.min_trust_ratio),
      max_evictions_per_edge: Number(recoveryForm.max_evictions_per_edge),
      max_replications_per_edge: Number(recoveryForm.max_replications_per_edge),
    }, setLatestRecovery);

  const loadRecoveryHistory = () =>
    runAction(
      "recoveryHistory",
      endpoints.recoveryHistory,
      undefined,
      setHistory,
      "GET"
    );

  const exportBackendMetrics = async (format) => {
    const key = `metricsExport${format.toUpperCase()}`;
    setLoadingAction(key);
    setErrors((previous) => ({ ...previous, [key]: "" }));
    try {
      const filename = `edgeguard-metrics.${format}`;
      await downloadApiFile(
        format === "json" ? endpoints.exportMetricsJson : endpoints.exportMetricsCsv,
        filename
      );
      setExperimentLog((previous) => [
        {
          id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
          timestamp: new Date().toLocaleTimeString(),
          operation: key,
          success: true,
          data: { filename },
        },
        ...previous,
      ].slice(0, 100));
    } catch (error) {
      const message = getErrorMessage(error);
      setErrors((previous) => ({ ...previous, [key]: message }));
      setExperimentLog((previous) => [
        {
          id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
          timestamp: new Date().toLocaleTimeString(),
          operation: key,
          success: false,
          error: message,
        },
        ...previous,
      ].slice(0, 100));
    } finally {
      setLoadingAction("");
    }
  };

  const attackStats = latestAttack || {};
  const discrimination = latestDiscrimination || {};
  const recovery = latestRecovery || {};

  const totalRequests = attackStats.processed_requests;

  const hitRatio =
    attackStats.hit_ratio ??
    attackStats.cache_hit_ratio ??
    null;

  const currentClassification =
    discrimination.results?.[0]?.classification ||
    "Awaiting analysis";

  const overviewMetrics = [
      {
        title: "Latest simulation requests",
        value: formatNumber(totalRequests),
        subtitle: latestAttack ? "Latest attack simulation response" : "Run a scenario to populate",
        icon: Activity,
        accent: "indigo",
      },
      {
        title: "Latest cache hit ratio",
        value: hitRatio == null ? "—" : formatPercent(hitRatio),
        subtitle: "Reported by the simulation API",
        icon: Zap,
        accent: "emerald",
      },
      {
        title: "Attack-labelled requests",
        value: latestAttack
          ? formatNumber(attackStats.attack_requests)
          : "—",
        subtitle: "Latest simulation only",
        icon: ShieldAlert,
        accent: "rose",
      },
      {
        title: "Recovery actions",
        value: latestRecovery
          ? formatNumber(Array.isArray(recovery.actions) ? recovery.actions.length : null)
          : "—",
        subtitle: "Proposed or executed actions in latest run",
        icon: RefreshCw,
        accent: "cyan",
      },
  ];

  const online = backendStatus === "online";
  const currentPage = NAV_ITEMS.find((item) => item.id === activePage) || NAV_ITEMS[0];

  function clearResults() {
    setResults({});
    setErrors({});
    setLatestAttack(null);
    setLatestDiscrimination(null);
    setLatestTrustedDemand(null);
    setLatestRecovery(null);
    setLatestEvaluation(null);
    setHistory(null);
    setExperimentLog([]);
  }

  function downloadExperiments() {
    const blob = new Blob([JSON.stringify(experimentLog, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "edgeguard-experiment-results.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-200">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col border-r border-slate-800 bg-[#0c121e] lg:flex">
        <div className="flex h-[76px] items-center gap-3 border-b border-slate-800 px-5">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/15 text-indigo-300">
            <ShieldCheck size={23} />
          </div>
          <div>
            <div className="text-sm font-bold tracking-wide text-white">EdgeGuard</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-[0.15em] text-slate-500">
              Intelligent CDN Security
            </div>
          </div>
        </div>

        <nav className="space-y-5 px-4 pt-6">
          {NAV_GROUPS.map((group) => (
            <div key={group}>
              <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                {group}
              </div>
              <div className="space-y-1">
                {NAV_ITEMS.filter((item) => item.group === group).map(({ id, label, icon: Icon }) => (
                  <button
                    key={id}
                    onClick={() => setActivePage(id)}
                    aria-current={activePage === id ? "page" : undefined}
                    className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition ${activePage === id
                      ? "bg-indigo-500/15 font-medium text-indigo-200"
                      : "text-slate-400 hover:bg-slate-800/60 hover:text-white"
                      }`}
                  >
                    <Icon size={17} />
                    <span>{label}</span>
                    {activePage === id && <ChevronRight className="ml-auto" size={15} />}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="mt-auto p-4">
          <div className="rounded-xl border border-slate-800 bg-[#101724] p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-medium text-slate-300">
              <Server size={14} />
              Simulator connection
            </div>
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${online ? "bg-emerald-400" : backendStatus === "checking" ? "animate-pulse bg-amber-400" : "bg-rose-400"
                }`} />
              <span className="text-xs text-slate-400">
                {online ? "Connected" : backendStatus === "checking" ? "Checking…" : "Disconnected"}
              </span>
            </div>
            {backendError && (
              <p className="mt-2 text-[11px] leading-4 text-rose-300">
                {backendError}
              </p>
            )}
            <button
              onClick={() => {
                setBackendStatus("checking");
                refreshBackend();
              }}
              disabled={backendStatus === "checking"}
              className="secondary-button mt-3 w-full"
            >
              <RefreshCw className={backendStatus === "checking" ? "animate-spin" : ""} size={13} />
              {backendStatus === "checking" ? "Checking…" : "Check connection"}
            </button>
          </div>
        </div>
      </aside>

      <div className="lg:pl-64">
        <header className="sticky top-0 z-10 flex min-h-[76px] items-center justify-between gap-3 border-b border-slate-800 bg-[#090d16]/95 px-4 backdrop-blur sm:px-7">
          <div>
            <div className="text-xs text-slate-500">
              EdgeGuard <span className="px-1 text-slate-700">/</span> {currentPage.group}
            </div>
            <h1 className="mt-1 text-base font-semibold text-white sm:text-lg">
              {currentPage.label}
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <StatusPill status={online ? "good" : backendStatus === "checking" ? "warning" : "bad"}>
              {online ? "Connected" : backendStatus === "checking" ? "Checking" : "Offline"}
            </StatusPill>
          </div>
        </header>

        <main className="mx-auto max-w-[1600px] p-4 sm:p-7">
          <div className="mb-6 flex gap-2 overflow-x-auto pb-1 lg:hidden">
            {NAV_ITEMS.map(({ id, label }) => (
              <button
                key={id}
                onClick={() => setActivePage(id)}
                aria-current={activePage === id ? "page" : undefined}
                className={`shrink-0 rounded-lg px-3 py-2 text-xs ${activePage === id
                    ? "bg-indigo-500/20 text-indigo-200"
                    : "border border-slate-800 text-slate-400"
                  }`}
              >
                {label}
              </button>
            ))}
          </div>

          {activePage === "overview" && (
            <>
              <div className="mb-7 flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
                <div>
                  <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.16em] text-indigo-300">
                    <Activity size={15} />
                    Live simulation
                  </div>
                  <h2 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                    Distributed CDN Network
                  </h2>
                  <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
                    Watch requests travel between the origin and edge caches. Trigger a request
                    or traffic scenario to see cache state and network metrics update.
                  </p>
                </div>
                <button onClick={() => setActivePage("attacks")} className="primary-button">
                  <Play size={15} />
                  Run an experiment
                  <ChevronRight size={15} />
                </button>
              </div>

              <NetworkSimulation
                topology={networkTopology}
                stats={networkStats}
                events={networkEvents}
                error={networkError}
                flow={networkFlow}
                online={online}
                busy={Boolean(loadingAction)}
                selectedEdgeId={systemForm.edge_id}
                onEdgeChange={updateTargetEdge}
                onSendRequest={runManualRequest}
                onRunScenario={runAttack}
              />

              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                {overviewMetrics.map((metric) => (
                  <MetricCard key={metric.title} {...metric} />
                ))}
              </div>

              <div className="mt-5 grid gap-5 xl:grid-cols-2">
                <ResultPanel
                  title="Latest attack simulation"
                  data={results.attack}
                  error={errors.attack}
                  loading={loadingAction === "attack"}
                />
                <ResultPanel
                  title="Latest recovery analysis"
                  data={results.recovery}
                  error={errors.recovery}
                  loading={loadingAction === "recovery"}
                />
              </div>
            </>
          )}

          {activePage === "attacks" && (
            <>
              <SectionHeading
                eyebrow="Traffic generation"
                title="Attack Simulation"
                description="Generate controlled traffic patterns in the local simulator. Recent requests can be analyzed and used in trusted-demand, placement, and recovery workflows."
                icon={ShieldAlert}
              />
              <NetworkSimulation
                topology={networkTopology}
                stats={networkStats}
                events={networkEvents}
                error={networkError}
                flow={networkFlow}
                online={online}
                busy={Boolean(loadingAction)}
                showControls={false}
              />
              <div className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
                <section className="panel p-5">
                  <h3 className="mb-4 font-semibold text-white">Scenario configuration</h3>
                  <div className="space-y-4">
                    <Field label="Attack / traffic scenario">
                      <select
                        className="field"
                        value={attackForm.scenario}
                        onChange={(e) => setAttackForm({ ...attackForm, scenario: e.target.value })}
                      >
                        {SCENARIOS.map((scenario) => (
                          <option key={scenario.value} value={scenario.value}>
                            {scenario.label}
                          </option>
                        ))}
                      </select>
                      <span className="mt-2 block text-xs leading-5 text-slate-500">
                        {SCENARIOS.find((s) => s.value === attackForm.scenario)?.description}
                      </span>
                    </Field>
                    <Field label="Edge ID">
                      <select
                        className="field"
                        value={attackForm.edge_id}
                        onChange={(event) => updateTargetEdge(event.target.value)}
                      >
                        {(networkTopology?.edges || []).map((edge) => (
                          <option key={edge.id} value={edge.id}>
                            {edge.id} — {edge.location || edge.name}
                          </option>
                        ))}
                      </select>
                    </Field>
                    <Field label="Request count">
                      <input
                        className="field"
                        type="number"
                        min="10"
                        max="5000"
                        value={attackForm.request_count}
                        onChange={(e) => setAttackForm({ ...attackForm, request_count: e.target.value })}
                      />
                    </Field>
                    <Field label="Random seed">
                      <input
                        className="field"
                        type="number"
                        value={attackForm.seed}
                        onChange={(e) => setAttackForm({ ...attackForm, seed: e.target.value })}
                      />
                    </Field>
                    <button
                      className="primary-button w-full"
                      disabled={!online || loadingAction === "attack" || Number(attackForm.request_count) < 10 || Number(attackForm.request_count) > 5000}
                      onClick={runAttack}
                    >
                      {loadingAction === "attack" ? <LoaderCircle className="animate-spin" size={16} /> : <Play size={16} />}
                      Run traffic simulation
                    </button>
                    {!online && <p className="text-xs text-rose-300">Backend connection required.</p>}
                  </div>
                </section>
                <div className="space-y-5">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <MetricCard
                      title="Requests"
                      value={                      formatNumber(attackStats.processed_requests)}
                      subtitle="From latest simulation response"
                      icon={Activity}
                    />
                    <MetricCard
                      title="Cache hit ratio"
                      value={formatPercent(attackStats.hit_ratio ?? attackStats.cache_hit_ratio)}
                      subtitle="Reported by backend"
                      icon={Zap}
                      accent="emerald"
                    />
                    <MetricCard
                      title="Origin requests"
                      value={formatNumber(attackStats.origin_requests)}
                      subtitle="Requests served by origin"
                      icon={Cloud}
                      accent="cyan"
                    />
                    <MetricCard
                      title="Origin traffic"
                      value={formatBytes(attackStats.origin_bytes_transferred)}
                      subtitle="Origin bytes transferred"
                      icon={Database}
                      accent="amber"
                    />
                  </div>
                  <ResultPanel
                    title="Scenario results"
                    data={results.attack}
                    error={errors.attack}
                    loading={loadingAction === "attack"}
                  />
                </div>
              </div>
            </>
          )}

          {activePage === "detection" && (
            <>
              <SectionHeading
                eyebrow="Traffic analysis"
                title="Traffic Detection & Trusted Demand"
                description="Analyze recorded request windows, evaluate scenario-labelled traffic, and estimate which content requests should contribute to trusted demand."
                icon={BrainCircuit}
              />
              <section className="panel mb-5 p-5">
                <div className="grid gap-4 md:grid-cols-3">
                  <Field label="Edge filter">
                    <select
                      className="field"
                      value={recoveryForm.edge_id}
                      onChange={(e) => setRecoveryForm({ ...recoveryForm, edge_id: e.target.value })}
                    >
                      <option value="">All edges</option>
                      <option value="edge-hyd">edge-hyd — Hyderabad</option>
                      <option value="edge-mum">edge-mum — Mumbai</option>
                      <option value="edge-del">edge-del — Delhi</option>
                    </select>
                  </Field>
                  <Field label="Maximum events to analyze">
                    <input
                      className="field"
                      type="number"
                      min="1"
                      value={recoveryForm.max_events}
                      onChange={(e) => setRecoveryForm({ ...recoveryForm, max_events: e.target.value })}
                    />
                  </Field>
                  <div className="flex items-end">
                    <button
                      className="primary-button w-full"
                      disabled={!online || Boolean(loadingAction)}
                      onClick={runDiscrimination}
                    >
                      {loadingAction === "discrimination" ? <LoaderCircle className="animate-spin" size={15} /> : <Shield size={15} />}
                      Analyze traffic
                    </button>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={runDemandTraining}
                  >
                    <BrainCircuit size={14} />
                    Train demand model
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={runDemandEvaluation}
                  >
                    <Gauge size={14} />
                    Evaluate demand forecast
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={runDemandPredictions}
                  >
                    <Activity size={14} />
                    Predict demand
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={runAnomalyTraining}
                  >
                    <ShieldAlert size={14} />
                    Train anomaly detector
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={runAnomalyEvaluation}
                  >
                    <Gauge size={14} />
                    Evaluate anomaly detector
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={runAnomalyAnalysis}
                  >
                    <Activity size={14} />
                    Analyze anomalies
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={runEvaluation}
                  >
                    <FileBarChart2 size={14} />
                    Evaluate scenarios
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={runTrustedDemand}
                  >
                    <BrainCircuit size={14} />
                    Estimate trusted demand
                  </button>
                </div>
              </section>

              <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <MetricCard
                  title="Classification"
                  value={String(currentClassification).replaceAll("_", " ")}
                  subtitle="Latest discrimination response"
                  icon={ShieldAlert}
                  accent="violet"
                />
                <MetricCard
                  title="Evaluation accuracy"
                  value={latestEvaluation?.accuracy == null ? "—" : formatPercent(latestEvaluation.accuracy)}
                  subtitle="Synthetic or labelled evaluation data"
                  icon={Gauge}
                  accent="emerald"
                />
                <MetricCard
                  title="Trusted-demand entries"
                  value={formatNumber(latestTrustedDemand?.results_count)}
                  subtitle="Field depends on backend response schema"
                  icon={CheckCircle2}
                  accent="cyan"
                />
                <MetricCard
                  title="Evaluation windows"
                  value={formatNumber(latestEvaluation?.evaluation_windows)}
                  subtitle="Reported by evaluation endpoint"
                  icon={Activity}
                  accent="amber"
                />
              </div>

              <div className="grid gap-5 xl:grid-cols-2">
                <ResultPanel
                  title="Demand model training"
                  data={results.demandTraining}
                  error={errors.demandTraining}
                  loading={loadingAction === "demandTraining"}
                />
                <ResultPanel
                  title="Demand forecast evaluation"
                  data={results.demandEvaluation}
                  error={errors.demandEvaluation}
                  loading={loadingAction === "demandEvaluation"}
                />
                <ResultPanel
                  title="Demand predictions"
                  data={results.demandPredictions}
                  error={errors.demandPredictions}
                  loading={loadingAction === "demandPredictions"}
                />
                <ResultPanel
                  title="Anomaly detector training"
                  data={results.anomalyTraining}
                  error={errors.anomalyTraining}
                  loading={loadingAction === "anomalyTraining"}
                />
                <ResultPanel
                  title="Anomaly detector evaluation"
                  data={results.anomalyEvaluation}
                  error={errors.anomalyEvaluation}
                  loading={loadingAction === "anomalyEvaluation"}
                />
                <ResultPanel
                  title="Anomaly analysis"
                  data={results.anomalyAnalysis}
                  error={errors.anomalyAnalysis}
                  loading={loadingAction === "anomalyAnalysis"}
                />
                <ResultPanel
                  title="Traffic discrimination"
                  data={results.discrimination}
                  error={errors.discrimination}
                  loading={loadingAction === "discrimination"}
                />
                <ResultPanel
                  title="Discrimination evaluation"
                  data={results.evaluation}
                  error={errors.evaluation}
                  loading={loadingAction === "evaluation"}
                />
                <ResultPanel
                  title="Trusted-demand estimation"
                  data={results.trustedDemand}
                  error={errors.trustedDemand}
                  loading={loadingAction === "trustedDemand"}
                />
              </div>
            </>
          )}

          {activePage === "placement" && (
            <>
              <SectionHeading
                eyebrow="Cache optimization"
                title="Attack-Resistant Predictive Cache Placement"
                description="Rank cache-placement candidates using predicted and trusted demand. Keep apply mode disabled while inspecting recommendations."
                icon={Layers3}
              />
              <div className="grid gap-5 xl:grid-cols-[0.85fr_1.15fr]">
                <section className="panel p-5">
                  <h3 className="mb-4 font-semibold text-white">Placement parameters</h3>
                  <div className="space-y-4">
                    <Field label="Target edge">
                      <select
                        className="field"
                        value={placementForm.edge_id}
                        onChange={(e) => setPlacementForm({ ...placementForm, edge_id: e.target.value })}
                      >
                        <option value="">All eligible edges</option>
                        <option value="edge-hyd">edge-hyd — Hyderabad</option>
                        <option value="edge-mum">edge-mum — Mumbai</option>
                        <option value="edge-del">edge-del — Delhi</option>
                      </select>
                    </Field>
                    <Field label="Prediction limit">
                      <input className="field" type="number" min="1" max="1000" value={placementForm.prediction_limit}
                        onChange={(e) => setPlacementForm({ ...placementForm, prediction_limit: e.target.value })} />
                    </Field>
                    <Field label="Maximum historical events">
                      <input className="field" type="number" min="1" value={placementForm.max_events}
                        onChange={(e) => setPlacementForm({ ...placementForm, max_events: e.target.value })} />
                    </Field>
                    <Field label="Prediction window size">
                      <input className="field" type="number" min="1" value={placementForm.window_size}
                        onChange={(e) => setPlacementForm({ ...placementForm, window_size: e.target.value })} />
                    </Field>
                    <Field label="Uncertainty penalty">
                      <input className="field" type="number" min="0" step="0.1" value={placementForm.uncertainty_penalty}
                        onChange={(e) => setPlacementForm({ ...placementForm, uncertainty_penalty: e.target.value })} />
                    </Field>
                    <Toggle
                      label="Apply placement to caches"
                      checked={placementForm.apply_placement}
                      onChange={(checked) => setPlacementForm({ ...placementForm, apply_placement: checked })}
                      description="Off means recommendations only. On asks the backend to apply supported cache insertions."
                    />
                    <button
                      className="primary-button w-full"
                      disabled={!online || Boolean(loadingAction)}
                      onClick={runPlacement}
                    >
                      {loadingAction === "placement" ? <LoaderCircle className="animate-spin" size={16} /> : <Layers3 size={16} />}
                      Calculate placement
                    </button>
                  </div>
                </section>
                <div className="space-y-5">
                  <div className="panel p-5">
                    <div className="flex items-center gap-2">
                      <BrainCircuit size={18} className="text-violet-300" />
                      <h3 className="font-semibold text-white">Placement objective</h3>
                    </div>
                    <div className="my-4 rounded-lg border border-slate-800 bg-[#0b111c] p-4 text-center">
                      <p className="text-sm text-slate-200">
                        Placement score ∝ Trusted predicted demand × Network benefit
                      </p>
                      <div className="my-2 border-t border-slate-700" />
                      <p className="text-sm text-slate-200">
                        Content size × Uncertainty penalty
                      </p>
                    </div>
                    <p className="text-xs leading-5 text-slate-500">
                      This score is a project heuristic and does not guarantee globally
                      optimal placement.
                    </p>
                  </div>
                  <ResultPanel
                    title="Placement recommendations"
                    data={results.placement}
                    error={errors.placement}
                    loading={loadingAction === "placement"}
                  />
                </div>
              </div>
            </>
          )}

          {activePage === "recovery" && (
            <>
              <SectionHeading
                eyebrow="Recovery coordination"
                title="Adaptive Recovery & Multi-Edge Coordination"
                description="Inspect attack-associated cached content and trusted-content coordination. Dry-run mode reports proposed actions without asking the backend to modify caches."
                icon={RefreshCw}
              />
              <div className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
                <section className="panel p-5">
                  <h3 className="mb-4 font-semibold text-white">Recovery configuration</h3>
                  <div className="space-y-4">
                    <Field label="Edge filter">
                      <select className="field" value={recoveryForm.edge_id}
                        onChange={(e) => setRecoveryForm({ ...recoveryForm, edge_id: e.target.value })}>
                        <option value="">All edges</option>
                        <option value="edge-hyd">edge-hyd — Hyderabad</option>
                        <option value="edge-mum">edge-mum — Mumbai</option>
                        <option value="edge-del">edge-del — Delhi</option>
                      </select>
                    </Field>
                    <div className="grid gap-3 sm:grid-cols-2">
                      <Field label="Minimum requests per content">
                        <input className="field" type="number" min="1" value={recoveryForm.min_content_requests}
                          onChange={(e) => setRecoveryForm({ ...recoveryForm, min_content_requests: e.target.value })} />
                      </Field>
                      <Field label="Maximum events">
                        <input className="field" type="number" min="1" value={recoveryForm.max_events}
                          onChange={(e) => setRecoveryForm({ ...recoveryForm, max_events: e.target.value })} />
                      </Field>
                      <Field label="Attack ratio threshold">
                        <input className="field" type="number" min="0" max="1" step="0.05" value={recoveryForm.attack_ratio_threshold}
                          onChange={(e) => setRecoveryForm({ ...recoveryForm, attack_ratio_threshold: e.target.value })} />
                      </Field>
                      <Field label="Minimum trust ratio">
                        <input className="field" type="number" min="0" max="1" step="0.05" value={recoveryForm.min_trust_ratio}
                          onChange={(e) => setRecoveryForm({ ...recoveryForm, min_trust_ratio: e.target.value })} />
                      </Field>
                      <Field label="Maximum evictions per edge">
                        <input className="field" type="number" min="0" value={recoveryForm.max_evictions_per_edge}
                          onChange={(e) => setRecoveryForm({ ...recoveryForm, max_evictions_per_edge: e.target.value })} />
                      </Field>
                      <Field label="Maximum replications per edge">
                        <input className="field" type="number" min="0" value={recoveryForm.max_replications_per_edge}
                          onChange={(e) => setRecoveryForm({ ...recoveryForm, max_replications_per_edge: e.target.value })} />
                      </Field>
                    </div>
                    <Toggle
                      label="Coordinate trusted content across edges"
                      checked={recoveryForm.coordinate_edges}
                      onChange={(checked) => setRecoveryForm({ ...recoveryForm, coordinate_edges: checked })}
                      description="Allow the backend to propose coordination for trusted content observed in recorded demand."
                    />
                    <Toggle
                      label="Apply recovery actions"
                      checked={recoveryForm.apply_recovery}
                      onChange={(checked) => setRecoveryForm({ ...recoveryForm, apply_recovery: checked })}
                      description="Off runs a dry-run analysis. On requests actual cache changes where supported."
                    />
                    {recoveryForm.apply_recovery && (
                      <div className="flex gap-2 rounded-lg border border-amber-400/20 bg-amber-400/5 p-3 text-xs leading-5 text-amber-200">
                        <AlertTriangle className="mt-0.5 shrink-0" size={15} />
                        Apply mode can modify the current in-memory caches.
                      </div>
                    )}
                    <button
                      className="primary-button w-full"
                      disabled={!online || Boolean(loadingAction)}
                      onClick={runRecovery}
                    >
                      {loadingAction === "recovery" ? <LoaderCircle className="animate-spin" size={16} /> : <RefreshCw size={16} />}
                      Run recovery analysis
                    </button>
                    <button
                      className="secondary-button w-full"
                      disabled={!online || Boolean(loadingAction)}
                      onClick={loadRecoveryHistory}
                    >
                      {loadingAction === "recoveryHistory" ? (
                        <LoaderCircle className="animate-spin" size={15} />
                      ) : (
                        <Clock3 size={15} />
                      )}
                      Load recovery history
                    </button>
                  </div>
                </section>

                <div className="space-y-5">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <MetricCard
                      title="Events analyzed"
                      value={formatNumber(recovery.events_analyzed)}
                      subtitle="Latest recovery run"
                      icon={Activity}
                    />
                    <MetricCard
                      title="Edges analyzed"
                      value={formatNumber(recovery.edges_analyzed)}
                      subtitle="Edges in current event window"
                      icon={Network}
                      accent="cyan"
                    />
                    <MetricCard
                      title="Evictions completed"
                      value={formatNumber(
                        latestRecovery && Array.isArray(recovery.edge_summaries)
                          ? recovery.edge_summaries.reduce(
                          (sum, edge) => sum + Number(edge.evictions_completed || 0), 0
                            )
                          : null
                      )}
                      subtitle="Reported successful evictions"
                      icon={Trash2}
                      accent="rose"
                    />
                    <MetricCard
                      title="Replications completed"
                      value={formatNumber(
                        latestRecovery && Array.isArray(recovery.edge_summaries)
                          ? recovery.edge_summaries.reduce(
                          (sum, edge) => sum + Number(edge.replications_completed || 0), 0
                            )
                          : null
                      )}
                      subtitle="Reported successful insertions"
                      icon={GitBranch}
                      accent="emerald"
                    />
                  </div>
                  <ResultPanel
                    title="Recovery actions and edge summaries"
                    data={results.recovery}
                    error={errors.recovery}
                    loading={loadingAction === "recovery"}
                  />
                  <ResultPanel
                    title="Recovery run history"
                    data={history}
                    error={errors.recoveryHistory}
                    loading={loadingAction === "recoveryHistory"}
                    emptyMessage="No recovery runs have been recorded yet."
                  />
                </div>
              </div>
            </>
          )}

          {activePage === "experiments" && (
            <>
              <SectionHeading
                eyebrow="Offline experiments"
                title="Experiment Evaluation"
                description="Replay preserved datasets, generate requests, configure cache policies, inspect backend metrics, and export both the server-side experiment report and this dashboard session log."
                icon={FileBarChart2}
              />
              <section className="panel mb-5 p-5">
                <h3 className="mb-4 font-semibold text-white">CDN and dataset controls</h3>
                <div className="grid gap-4 lg:grid-cols-3">
                  <div className="space-y-3">
                    <Field label="Edge">
                      <select
                        className="field"
                        value={systemForm.edge_id}
                        onChange={(event) => updateTargetEdge(event.target.value)}
                      >
                        {(networkTopology?.edges || []).map((edge) => (
                          <option key={edge.id} value={edge.id}>
                            {edge.id} — {edge.location || edge.name}
                          </option>
                        ))}
                      </select>
                    </Field>
                    <Field label="Cache strategy">
                      <select
                        className="field"
                        value={systemForm.strategy}
                        onChange={(event) => setSystemForm({ ...systemForm, strategy: event.target.value })}
                      >
                        {["LRU", "LFU", "FIFO", "PREDICTIVE"].map((strategy) => (
                          <option key={strategy} value={strategy}>{strategy}</option>
                        ))}
                      </select>
                    </Field>
                    <button
                      className="secondary-button w-full"
                      disabled={!online || Boolean(loadingAction)}
                      onClick={runCacheStrategy}
                    >
                      Apply cache strategy
                    </button>
                  </div>
                  <div className="space-y-3">
                    <Field label="Content ID">
                      <input
                        className="field"
                        value={systemForm.content_id}
                        onChange={(event) => setSystemForm({ ...systemForm, content_id: event.target.value })}
                      />
                    </Field>
                    <Field label="Response size (bytes)">
                      <input
                        className="field"
                        type="number"
                        min="0"
                        value={systemForm.response_size_bytes}
                        onChange={(event) => setSystemForm({ ...systemForm, response_size_bytes: event.target.value })}
                      />
                    </Field>
                    <button
                      className="primary-button w-full"
                      disabled={!online || Boolean(loadingAction) || !systemForm.content_id.trim()}
                      onClick={runManualRequest}
                    >
                      <Play size={14} />
                      Simulate one request
                    </button>
                  </div>
                  <div className="space-y-3">
                    <Field label="Dataset">
                      <select
                        className="field"
                        value={systemForm.dataset}
                        onChange={(event) => setSystemForm({ ...systemForm, dataset: event.target.value })}
                      >
                        <option value="synthetic">Synthetic attack scenarios</option>
                        <option value="wikimedia">Wikimedia trace</option>
                        <option value="web_logs">Web access logs</option>
                      </select>
                    </Field>
                    <Field label="Replay limit">
                      <input
                        className="field"
                        type="number"
                        min="1"
                        max="10000"
                        value={systemForm.dataset_limit}
                        onChange={(event) => setSystemForm({ ...systemForm, dataset_limit: event.target.value })}
                      />
                    </Field>
                    <button
                      className="primary-button w-full"
                      disabled={!online || Boolean(loadingAction) || Number(systemForm.dataset_limit) < 1 || Number(systemForm.dataset_limit) > 10000}
                      onClick={runDatasetReplay}
                    >
                      <Database size={14} />
                      Replay dataset
                    </button>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={loadCacheStats}
                  >
                    <Layers3 size={14} />
                    Refresh cache statistics
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={loadMetrics}
                  >
                    <Gauge size={14} />
                    Refresh backend metrics
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={() => exportBackendMetrics("json")}
                  >
                    <ArrowDownRight size={14} />
                    Export backend JSON
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={() => exportBackendMetrics("csv")}
                  >
                    <ArrowDownRight size={14} />
                    Export backend CSV
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online || Boolean(loadingAction)}
                    onClick={resetBackend}
                  >
                    <Trash2 size={14} />
                    Reset backend state
                  </button>
                  <button
                    className="secondary-button"
                    disabled={!online}
                    onClick={refreshExperimentHistory}
                  >
                    <Clock3 size={14} />
                    Refresh saved runs
                  </button>
                </div>
                <div className="mt-5 grid gap-5 xl:grid-cols-2">
                  <ResultPanel
                    title="Cache statistics by edge"
                    data={results.cacheStats}
                    error={errors.cacheStats}
                    loading={loadingAction === "cacheStats"}
                  />
                  <ResultPanel
                    title="Backend performance metrics"
                    data={results.metrics}
                    error={errors.metrics}
                    loading={loadingAction === "metrics"}
                  />
                  <ResultPanel
                    title="Last CDN or dataset operation"
                    data={results.datasetReplay || results.simulateRequest || results.cacheStrategy}
                    error={errors.datasetReplay || errors.simulateRequest || errors.cacheStrategy}
                    loading={["datasetReplay", "simulateRequest", "cacheStrategy"].includes(loadingAction)}
                  />
                </div>
                {(errors.metricsExportJSON || errors.metricsExportCSV) && (
                  <p className="mt-3 text-xs text-rose-300">
                    {errors.metricsExportJSON || errors.metricsExportCSV}
                  </p>
                )}
              </section>
              <div className="mb-5">
                <ResultPanel
                  title="Saved local experiment history"
                  data={savedExperimentHistory}
                  error={savedHistoryError}
                  emptyMessage="No backend experiment runs have been saved yet."
                />
              </div>
              <div className="mb-5 grid gap-3 sm:grid-cols-3">
                <MetricCard
                  title="Recorded operations"
                  value={formatNumber(experimentLog.length)}
                  subtitle="Current frontend session"
                  icon={Activity}
                />
                <MetricCard
                  title="Successful operations"
                  value={formatNumber(experimentLog.filter((item) => item.success).length)}
                  subtitle="HTTP requests that returned successfully"
                  icon={CheckCircle2}
                  accent="emerald"
                />
                <MetricCard
                  title="Failed operations"
                  value={formatNumber(experimentLog.filter((item) => !item.success).length)}
                  subtitle="Errors retained for debugging"
                  icon={AlertTriangle}
                  accent="rose"
                />
              </div>

              <section className="panel overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 p-4">
                  <div>
                    <h3 className="font-semibold text-white">Experiment log</h3>
                    <p className="mt-1 text-xs text-slate-500">
                      This session log is temporary; successful traffic and model evaluation runs are also saved locally by the backend.
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      className="secondary-button"
                      disabled={!experimentLog.length}
                      onClick={downloadExperiments}
                    >
                      <ArrowDownRight size={14} />
                      Export JSON
                    </button>
                    <button className="secondary-button" onClick={clearResults}>
                      <Trash2 size={14} />
                      Clear log
                    </button>
                  </div>
                </div>

                <div className="data-scroll">
                  <table className="w-full min-w-[640px] text-left text-xs">
                    <thead className="bg-[#0b111c] text-slate-500">
                      <tr>
                        <th className="px-4 py-3 font-medium">Time</th>
                        <th className="px-4 py-3 font-medium">Operation</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                        <th className="px-4 py-3 font-medium">Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {experimentLog.map((entry) => (
                        <tr key={entry.id} className="border-t border-slate-800">
                          <td className="whitespace-nowrap px-4 py-3 text-slate-400">{entry.timestamp}</td>
                          <td className="px-4 py-3 font-medium text-slate-200">{entry.operation}</td>
                          <td className="px-4 py-3">
                            <StatusPill status={entry.success ? "good" : "bad"}>
                              {entry.success ? "Success" : "Failed"}
                            </StatusPill>
                          </td>
                          <td className="max-w-sm px-4 py-3 text-slate-400">
                            {entry.success
                              ? `${Object.keys(entry.data || {}).length} response fields`
                              : entry.error}
                          </td>
                        </tr>
                      ))}
                      {!experimentLog.length && (
                        <tr>
                          <td colSpan="4" className="px-4 py-12 text-center text-slate-500">
                            No operations recorded. Run an experiment to populate this table.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              <div className="mt-5 grid gap-5 xl:grid-cols-2">
                <ResultPanel
                  title="Latest demand placement"
                  data={results.placement}
                  error={errors.placement}
                  loading={loadingAction === "placement"}
                />
                <ResultPanel
                  title="Latest trusted-demand estimate"
                  data={results.trustedDemand}
                  error={errors.trustedDemand}
                  loading={loadingAction === "trustedDemand"}
                />
              </div>
            </>
          )}

          <footer className="mt-10 flex flex-col justify-between gap-2 border-t border-slate-800 py-5 text-[11px] text-slate-600 sm:flex-row">
            <span>EdgeGuard · AI-Driven Attack-Resistant Predictive Caching</span>
          </footer>
        </main>
      </div>
    </div>
  );
}

export default App;
