import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import {
  testingApi,
  type CapabilityState,
  type DiscoveryResult,
  type HttpContractConfig,
  type HttpInlineEvidenceMapping,
  type ManagedProfile,
  type OpenApiCandidate,
  type ProbeResult,
  type SessionAuthReference,
  type SessionCredentialMetadata,
  type TargetPreset,
} from './testingApi';
import DiscoveryPanel from './DiscoveryPanel';
import EvidenceSources from './EvidenceSources';
import ApplicationContext from './ApplicationContext';

const defaultHttpConfig: HttpContractConfig = {
  method: 'POST',
  body_template: { input: '{{input}}' },
  headers: {},
  response: { text_path: 'answer' },
};
const DEFAULT_SAMPLE_INPUT = 'Hello. Please reply with a brief status confirmation.';
const UNRESOLVED_PLACEHOLDER_RE = /<REQUIRED:[A-Za-z0-9_.-]+>/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
const API_KEY_HEADER_NAME_RE = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
const AUTH_ROUTED_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'api-key',
  'x-auth-token',
  'cookie',
  'set-cookie',
]);
const TRANSPORT_RESERVED_HEADERS = new Set([
  'host',
  'content-length',
  'transfer-encoding',
  'connection',
  'x-secagent-operator',
  'x-secagent-validation',
]);
const DISALLOWED_API_KEY_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  ...TRANSPORT_RESERVED_HEADERS,
  'content-type',
  'accept',
  'accept-encoding',
  'user-agent',
  'origin',
  'referer',
  'sec-fetch-site',
]);

type AuthUiMode = 'none' | 'bearer' | 'api_key' | 'existing';
type HeaderRow = { id: string; key: string; value: string };

let nextHeaderRowId = 1;
function headersObjectToRows(headers?: Record<string, string> | null): HeaderRow[] {
  return Object.entries(headers ?? {})
    .filter(([k]) => k.toLowerCase() !== 'content-type')
    .map(([key, value]) => ({ id: `hdr-${nextHeaderRowId++}`, key, value }));
}

function validateHeaderRows(
  rows: HeaderRow[],
  activeSessionAuth?: SessionAuthReference | null,
): { error: string; authHeaderHint: { rowId: string; headerName: string } | null; headers: Record<string, string> } {
  const seen = new Set<string>(['content-type']);
  const sessionAuthHeader = activeSessionAuth?.header_name?.toLowerCase() ?? null;
  const out: Record<string, string> = {};
  for (const row of rows) {
    const key = row.key.trim();
    const val = row.value;
    if (!key && !val.trim()) continue;
    if (!key) {
      return { error: 'Enter a header name or remove the empty header row.', authHeaderHint: null, headers: out };
    }
    if (!HEADER_NAME_RE.test(key)) {
      return { error: `Header name "${key}" must use only ASCII letters, digits, and hyphens.`, authHeaderHint: null, headers: out };
    }
    const low = key.toLowerCase();
    if (AUTH_ROUTED_HEADERS.has(low)) {
      return {
        error: `Authentication header "${key}" cannot be saved as an ordinary header. Use the dedicated Authentication control instead.`,
        authHeaderHint: { rowId: row.id, headerName: key },
        headers: out,
      };
    }
    if (TRANSPORT_RESERVED_HEADERS.has(low)) {
      return { error: `Header "${key}" is controlled by the HTTP transport and cannot be added manually.`, authHeaderHint: null, headers: out };
    }
    if (low === 'content-type') {
      const mediaType = val.split(';', 1)[0].trim().toLowerCase();
      if (mediaType !== 'application/json') {
        return { error: 'Conflicting Content-Type header. HTTP JSON targets require application/json.', authHeaderHint: null, headers: out };
      }
      return { error: 'Content-Type: application/json is already included by default; remove the duplicate row.', authHeaderHint: null, headers: out };
    }
    if (sessionAuthHeader && low === sessionAuthHeader) {
      return { error: `Header "${key}" conflicts with the configured Authentication header.`, authHeaderHint: null, headers: out };
    }
    if (seen.has(low)) {
      return { error: `Duplicate HTTP header "${key}" (case-insensitive).`, authHeaderHint: null, headers: out };
    }
    seen.add(low);
    if (
      val.includes('{{') ||
      val.includes('}}') ||
      UNRESOLVED_PLACEHOLDER_RE.test(val) ||
      val.length > 256 ||
      /[\x00-\x1f\x7f]/.test(val)
    ) {
      return { error: `Header "${key}" value is invalid or contains unsupported template syntax.`, authHeaderHint: null, headers: out };
    }
    out[key] = val;
  }
  return { error: '', authHeaderHint: null, headers: out };
}

function buildRedactedPreviewHeaders(
  customHeaders?: Record<string, string> | null,
  credentialAlias?: string | null,
  sessionAuth?: SessionAuthReference | null,
): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(customHeaders ?? {}),
  };
  if (credentialAlias) {
    headers.Authorization = `Bearer [alias:${credentialAlias}]`;
  } else if (sessionAuth) {
    headers[sessionAuth.header_name] = sessionAuth.auth_type === 'bearer' ? 'Bearer [REDACTED]' : '[REDACTED]';
  }
  return headers;
}

function discoveredApiKeyHeader(candidate?: OpenApiCandidate | null): string | null {
  for (const scheme of candidate?.auth_schemes ?? []) {
    if (scheme.startsWith('apiKey:header:')) {
      const name = scheme.slice('apiKey:header:'.length).trim();
      if (name && name.toLowerCase() !== 'authorization') return name;
    }
    if (scheme.startsWith('header:')) {
      const name = scheme.slice('header:'.length).trim();
      if (name && name.toLowerCase() !== 'authorization') return name;
    }
  }
  return null;
}

function hasUnresolvedPlaceholder(value: unknown): boolean {
  if (typeof value === 'string') return UNRESOLVED_PLACEHOLDER_RE.test(value);
  if (Array.isArray(value)) return value.some(hasUnresolvedPlaceholder);
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).some(
      ([k, v]) => UNRESOLVED_PLACEHOLDER_RE.test(k) || hasUnresolvedPlaceholder(v),
    );
  }
  return false;
}

function setNestedField(obj: Record<string, unknown>, dottedName: string, value: unknown): Record<string, unknown> {
  const parts = dottedName.split('.').filter(Boolean);
  if (parts.length <= 1) return { ...obj, [dottedName]: value };
  const [head, ...tail] = parts;
  const existing = obj[head];
  const child = existing && typeof existing === 'object' && !Array.isArray(existing)
    ? (existing as Record<string, unknown>)
    : {};
  return { ...obj, [head]: setNestedField(child, tail.join('.'), value) };
}

function extractDottedPath(data: unknown, path: string | null | undefined): { found: boolean; value: unknown } {
  if (!path || !path.trim() || data === null || data === undefined) return { found: false, value: undefined };
  let cur: unknown = data;
  for (const seg of path.trim().split('.')) {
    if (Array.isArray(cur)) {
      const idx = Number.parseInt(seg, 10);
      if (Number.isNaN(idx) || idx < 0 || idx >= cur.length) return { found: false, value: undefined };
      cur = cur[idx];
    } else if (cur && typeof cur === 'object' && seg in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[seg];
    } else {
      return { found: false, value: undefined };
    }
  }
  return { found: true, value: cur };
}

function renderTemplatePreview(value: unknown, inputVal: string): unknown {
  if (typeof value === 'string') return value.replaceAll('{{input}}', inputVal);
  if (Array.isArray(value)) return value.map(item => renderTemplatePreview(item, inputVal));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = renderTemplatePreview(v, inputVal);
    }
    return out;
  }
  return value;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function httpContractSignature(
  endpoint: string,
  protocol: string,
  credAlias?: string | null,
  httpCfg?: HttpContractConfig | null,
  sessionAuth?: SessionAuthReference | null,
): string {
  if (protocol !== 'http-json') return JSON.stringify([endpoint, protocol]);
  const sessSig = sessionAuth ? `${sessionAuth.auth_type}:${sessionAuth.header_name.toLowerCase()}:${sessionAuth.ref_id}` : '';
  return JSON.stringify([endpoint, protocol, credAlias ?? '', sessSig, canonicalJson(httpCfg ?? null)]);
}

function parseCsvValues(raw: string): string[] {
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

function coerceTypedValue(raw: string, fieldType: string): unknown {
  if (fieldType === 'boolean') return raw === 'true';
  if (fieldType === 'integer') {
    const n = Number.parseInt(raw, 10);
    return Number.isNaN(n) ? raw : n;
  }
  if (fieldType === 'number') {
    const n = Number(raw);
    return Number.isNaN(n) ? raw : n;
  }
  return raw;
}

function authStatusLabel(candidate: OpenApiCandidate | null): { text: string; tone: string } {
  if (!candidate) return { text: 'Authentication not declared', tone: '' };
  const status = candidate.auth_status ?? (
    candidate.requires_auth
      ? (candidate.auth_scheme_supported === false ? 'unsupported' : 'required')
      : 'not_declared'
  );
  if (status === 'unsupported') return { text: 'Authentication unsupported', tone: 'is-unsupported' };
  if (status === 'required') return { text: 'Authentication required', tone: 'is-required' };
  if (status === 'may_be_required') return { text: 'Authentication may be required', tone: 'is-hint' };
  return { text: 'Authentication not declared', tone: '' };
}

function verificationBadgeLabel(probe: ProbeResult | null): string {
  if (!probe) return 'Connection unverified';
  if (probe.verification_state === 'connection_verified' || (probe.connection_status === 'succeeded' && probe.runtime_protocol_compatible === true)) {
    return 'Connection verified';
  }
  if (probe.verification_state === 'response_mapping_unresolved') {
    return 'Transport connected · Response mapping unresolved';
  }
  if (probe.verification_state === 'authentication_failed') return 'Authentication failed (HTTP 401)';
  if (probe.verification_state === 'permission_denied') return 'Permission denied (HTTP 403)';
  if (probe.verification_state === 'request_rejected') return `Request rejected (HTTP ${probe.http_status ?? 'error'})`;
  if (probe.verification_state === 'credentials_missing') return 'Missing server credentials';
  if (probe.verification_state === 'transport_failed') return 'Transport / network failure';
  return 'Connection failed';
}

const CAPABILITY_KEYS: [string, string][] = [
  ['response_behavior', 'Response behavior'],
  ['tool_intent', 'Model-reported tool intent'],
  ['agent_run', 'Agent-mediated run / actions'],
  ['runtime_execution', 'Actual runtime / code execution'],
  ['direct_tool_access', 'Direct tool / MCP access'],
];

const researchBot: ManagedProfile = {
  id: 'dvaa-researchbot', name: 'DVAA ResearchBot', platform_id: 'dvaa', platform_name: 'DVAA',
  protocol: 'openai-chat', endpoint: 'http://127.0.0.1:7015/v1/chat/completions',
  model: 'researchbot', timeout_seconds: 30,
};
const toolBotLab: ManagedProfile = {
  id: 'dvaa-toolbot-lab', name: 'DVAA ToolBot Lab',
  platform_id: 'dvaa', platform_name: 'DVAA', protocol: 'mcp-jsonrpc',
  endpoint: 'http://127.0.0.1:17022/mcp', model: 'toolbot-lab', timeout_seconds: 30,
};
const empty: ManagedProfile = { ...researchBot, id: '', name: '', platform_id: 'unknown', platform_name: 'Unknown', endpoint: '', model: '' };

function ProbeDiagnosticsPanel({
  probe,
  currentConfig,
  onApplyTextPath,
  onApplyCorrelationPath,
  onApplyStatusPath,
  onApplyEvidenceMapping,
}: {
  probe: ProbeResult;
  currentConfig?: HttpContractConfig | null;
  onApplyTextPath?: (path: string) => void;
  onApplyCorrelationPath?: (path: string) => void;
  onApplyStatusPath?: (path: string) => void;
  onApplyEvidenceMapping?: (mapping: HttpInlineEvidenceMapping) => void;
}) {
  const diag = probe.mapping_diagnostics;
  const sample = probe.response_sample;
  const activeTextPath = currentConfig?.response.text_path ?? diag?.configured_text_path ?? '';
  const localCheck = sample && activeTextPath ? extractDottedPath(sample, activeTextPath) : null;
  const localTextValid = localCheck ? (localCheck.found && typeof localCheck.value === 'string') : null;
  const localStatusPath = currentConfig?.response.status_path ?? diag?.configured_status_path ?? '';
  const completeVals = currentConfig?.response.complete_status_values ?? diag?.configured_complete_status_values ?? [];
  const incompleteVals = currentConfig?.response.incomplete_status_values ?? diag?.configured_incomplete_status_values ?? [];
  const completenessUnresolved = Boolean(
    localStatusPath && completeVals.length === 0 && incompleteVals.length === 0,
  ) || Boolean(diag?.completeness_unresolved && completeVals.length === 0 && incompleteVals.length === 0);

  return (
    <div className="probe-diagnostics" role="region" aria-label="Connection test diagnostics">
      <p>
        <strong>{verificationBadgeLabel(probe)}</strong>
        {probe.http_status !== null && probe.http_status !== undefined ? ` · HTTP ${probe.http_status}` : ''}
        {` · Requests sent: ${probe.target_request_count}`}
      </p>
      {probe.guidance && <p className="caption">{probe.guidance}</p>}
      {probe.extracted_output && (
        <div>
          <strong>Extracted output</strong>
          <pre className="probe-preview-pre">{probe.extracted_output}</pre>
        </div>
      )}
      {localCheck && activeTextPath && !probe.extracted_output && (
        <p role="status" className="caption">
          {localTextValid
            ? `Revised text path "${activeTextPath}" validated against the captured response sample (no extra request sent): ${String(localCheck.value).slice(0, 160)}`
            : `Configured text path "${activeTextPath}" does not resolve to a string in the captured response sample.`}
        </p>
      )}
      {completenessUnresolved && (
        <div className="readiness-warning" role="status">
          <strong>Evaluation readiness limitation:</strong> Status field <code>{localStatusPath}</code>
          {diag?.observed_status_value ? ` (observed "${diag.observed_status_value}")` : ''} has no confirmed complete/incomplete status values.
          {' '}<code>response_complete</code> remains unknown and semantic Judge evaluation will stay gated until you confirm status completion semantics in Advanced HTTP settings.
        </div>
      )}
      {!!diag?.evaluation_readiness_limitations?.length && !completenessUnresolved && (
        <ul className="caption">
          {diag.evaluation_readiness_limitations.map((lim, idx) => <li key={idx}>{lim}</li>)}
        </ul>
      )}
      {diag?.suggestions && (onApplyTextPath || onApplyCorrelationPath || onApplyStatusPath || onApplyEvidenceMapping) && (
        <div className="mapping-suggestions" aria-label="Suggested response mappings">
          <strong>Observed response mapping suggestions</strong>
          <p className="caption">Deterministic suggestions from the captured JSON sample. Review before applying; ambiguous fields are never auto-applied.</p>
          {!!diag.suggestions.text_path_candidates?.length && onApplyTextPath && (
            <ul>
              {diag.suggestions.text_path_candidates.map(cand => (
                <li key={`text-${cand.path}`}>
                  <span>Response text: <code>{cand.path}</code> ({cand.confidence}{cand.ambiguous ? ', ambiguous' : ''})</span>
                  <button type="button" onClick={() => onApplyTextPath(cand.path)}>Apply text path</button>
                </li>
              ))}
            </ul>
          )}
          {!!diag.suggestions.correlation_id_candidates?.length && onApplyCorrelationPath && (
            <ul>
              {diag.suggestions.correlation_id_candidates.map(cand => (
                <li key={`corr-${cand.path}`}>
                  <span>Correlation ID: <code>{cand.path}</code> ({cand.confidence})</span>
                  <button type="button" onClick={() => onApplyCorrelationPath(cand.path)}>Apply correlation path</button>
                </li>
              ))}
            </ul>
          )}
          {!!diag.suggestions.status_path_candidates?.length && onApplyStatusPath && (
            <ul>
              {diag.suggestions.status_path_candidates.map(cand => (
                <li key={`status-${cand.path}`}>
                  <span>Status field: <code>{cand.path}</code>{cand.observed_value ? ` (observed "${cand.observed_value}")` : ''} · confirm complete/incomplete values manually</span>
                  <button type="button" onClick={() => onApplyStatusPath(cand.path)}>Apply status path</button>
                </li>
              ))}
            </ul>
          )}
          {!!diag.suggestions.evidence_mapping_candidates?.length && onApplyEvidenceMapping && (
            <ul>
              {diag.suggestions.evidence_mapping_candidates.map(cand => (
                <li key={`ev-${cand.items}`}>
                  <span>
                    Inline evidence array: <code>{cand.items}</code> ({cand.items_observed} observed item{cand.items_observed === 1 ? '' : 's'}, target-reported only)
                    {cand.item_fields_observed ? ` · fields: ${Object.entries(cand.suggested_mapping).filter(([k]) => k !== 'items').map(([k, v]) => `${k}=${v}`).join(', ')}` : ' · no item fields inferred'}
                  </span>
                  {cand.item_fields_observed && (
                    <button type="button" onClick={() => onApplyEvidenceMapping(cand.suggested_mapping)}>Apply inline evidence mapping</button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      {probe.request_preview && (
        <details>
          <summary>Redacted request preview</summary>
          <pre className="probe-preview-pre">{`${probe.request_preview.method} ${probe.request_preview.url}\nHeaders: ${JSON.stringify(probe.request_preview.headers)}\nBody: ${probe.request_preview.body_preview}`}</pre>
        </details>
      )}
      {probe.response_preview && (
        <details open={!probe.extracted_output}>
          <summary>Bounded redacted response preview</summary>
          <pre className="probe-preview-pre">{probe.response_preview}</pre>
        </details>
      )}
    </div>
  );
}

export type ConnectionState = 'Not checked' | 'Checking' | 'Connected' | 'Connection failed';
export function targetKey(target?: TargetPreset) {
  return target ? JSON.stringify([target.id, target.profile_revision, target.policy_ref, target.endpoint, target.default_model]) : '';
}

export default function TargetManager({
  enabled,
  nonce,
  target,
  onChanged,
  onDiscoveryFlowChange,
  localSingleUser = false,
  toolbotLabEnabled = false,
  onConnectionChange,
  settingsMatch = true,
  configurationInvalid = false,
  evidenceEnabled = false,
  initialConnect = false,
  existingSelector,
  existingTargetIds = [],
  existingProfiles = [],
  credentialAliases = [],
  credentialAliasAvailability = {},
}: {
  existingTargetIds?: string[];
  existingProfiles?: TargetPreset[];
  credentialAliases?: string[];
  credentialAliasAvailability?: Record<string, string>;
  existingSelector?: ReactNode;
  initialConnect?: boolean;
  evidenceEnabled?: boolean;
  enabled: boolean;
  nonce: string;
  target?: TargetPreset;
  onChanged: (id: string) => void;
  onDiscoveryFlowChange?: (active: boolean) => void;
  localSingleUser?: boolean;
  toolbotLabEnabled?: boolean;
  onConnectionChange?: (key: string, state: ConnectionState) => void;
  settingsMatch?: boolean;
  configurationInvalid?: boolean;
}) {
  const [secret, setSecret] = useState(''), [unlocked, setUnlocked] = useState(false), [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<'create' | 'edit' | null>(null), [form, setForm] = useState<ManagedProfile>(empty);
  const [bodyJson, setBodyJson] = useState<string>(JSON.stringify(defaultHttpConfig.body_template, null, 2));
  const [bodyJsonError, setBodyJsonError] = useState<string>('');
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([]);
  const [authMode, setAuthMode] = useState<AuthUiMode>('none');
  const [apiKeyHeaderName, setApiKeyHeaderName] = useState<string>('X-API-Key');
  const [sessionSecretInput, setSessionSecretInput] = useState<string>('');
  const [sessionCredStatus, setSessionCredStatus] = useState<SessionCredentialMetadata | null>(null);
  const [sessionAuthBusy, setSessionAuthBusy] = useState<boolean>(false);
  const [sessionAuthError, setSessionAuthError] = useState<string>('');
  const [savedSessionInput, setSavedSessionInput] = useState<string>('');
  const [savedSessionBusy, setSavedSessionBusy] = useState<boolean>(false);
  const [savedSessionMessage, setSavedSessionMessage] = useState<string>('');
  const [selectedCandidate, setSelectedCandidate] = useState<OpenApiCandidate | null>(null);
  const [guidedFieldValues, setGuidedFieldValues] = useState<Record<string, string>>({});
  const [sampleInput, setSampleInput] = useState<string>(DEFAULT_SAMPLE_INPUT);
  const [expected, setExpected] = useState<string | null>(null), [checked, setChecked] = useState(false);
  const [confirmed, setConfirmed] = useState(false), [message, setMessage] = useState(''), [error, setError] = useState('');
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [discovering, setDiscovering] = useState(initialConnect), [discoveryId, setDiscoveryId] = useState<string | null>(null);
  const [discoveryResult, setDiscoveryResult] = useState<DiscoveryResult | null>(null);
  const [discoveryEndpoint, setDiscoveryEndpoint] = useState<string | null>(null);
  const [discoveryProtocol, setDiscoveryProtocol] = useState<ManagedProfile['protocol'] | null>(null);
  const [quickProbe, setQuickProbe] = useState<ProbeResult | null>(null), [quickConfirmed, setQuickConfirmed] = useState(false);
  const [quickError, setQuickError] = useState(''), [quickSavedProbe, setQuickSavedProbe] = useState(false);
  const [awaitingSelection, setAwaitingSelection] = useState(false);
  const [query, setQuery] = useState('');
  const [deleteCandidate, setDeleteCandidate] = useState<TargetPreset | null>(null);
  const [editingOriginal, setEditingOriginal] = useState<TargetPreset | null>(null), [platformConfirmed, setPlatformConfirmed] = useState(false);
  const carryProbe = useRef<{ id: string; revision: string; result: ProbeResult | null } | null>(null);
  const carryMessage = useRef<string>('');
  const pendingDraftRefs = useRef<Map<string, { scope_kind: 'discovery' | 'draft'; scope_id: string }>>(new Map());
  const sessionOpId = useRef(0);
  const savedSessionOpId = useRef(0);
  const [checking, setChecking] = useState(false), [probeFailed, setProbeFailed] = useState(false);
  const [probeKey, setProbeKey] = useState('');
  const identity = targetKey(target), current = useRef(identity + nonce), generation = useRef(0);
  if (current.current !== identity + nonce) { current.current = identity + nonce; generation.current++; }

  useEffect(() => {
    const carry = carryProbe.current;
    if (carry && target?.id === carry.id && target.profile_revision === carry.revision) {
      setProbe(carry.result); setProbeKey(identity + nonce); setQuickSavedProbe(true); carryProbe.current = null;
    } else { setProbe(null); setQuickSavedProbe(false); }
    const nextMsg = carryMessage.current; carryMessage.current = '';
    setConfirmed(false); setProbeFailed(false); setChecking(false); setBusy(false); setQuickConfirmed(false); setAwaitingSelection(false); setMessage(nextMsg); setError('');
    setSavedSessionInput(''); setSavedSessionBusy(false); setSavedSessionMessage('');
  }, [identity, nonce]);

  useEffect(() => () => { generation.current++; }, []);
  useEffect(() => { setConfirmed(false); }, [settingsMatch]);
  useEffect(() => { if (['stale', 'expired'].includes(target?.connection_verification?.status ?? '')) setProbe(null); }, [target?.connection_verification?.status]);

  const ownProbe = probeKey === identity + nonce ? probe : null;
  const connection: ConnectionState = !settingsMatch ? 'Not checked' : probeKey === identity + nonce && checking ? 'Checking' : probeKey === identity + nonce && probeFailed ? 'Connection failed' : ownProbe ?
    ownProbe.connection_status === 'succeeded' && ownProbe.runtime_protocol_compatible === true ? 'Connected' : 'Connection failed' :
    target?.connection_verification?.status === 'compatible' && target.connection_verification.profile_revision === target.profile_revision ? 'Connected' : 'Not checked';
  useEffect(() => { onConnectionChange?.(identity, connection); }, [identity, connection, onConnectionChange]);

  async function unlock() {
    if (!secret) return;
    setBusy(true); setError('');
    try {
      await testingApi.unlock(secret, nonce);
      setUnlocked(true);
      setMessage('Operator access verified for this browser session.');
    } catch {
      setError('Operator access was rejected. Check the local operator secret and service configuration.');
    } finally { setBusy(false); }
  }

  function releasePendingDraftRefs(exceptRefId?: string) {
    const entries = Array.from(pendingDraftRefs.current.entries());
    for (const [refId, scope] of entries) {
      if (exceptRefId && refId === exceptRefId) continue;
      pendingDraftRefs.current.delete(refId);
      if (nonce) {
        void testingApi
          .clearSessionCredential(
            { ref_id: refId, scope_kind: scope.scope_kind, scope_id: scope.scope_id },
            secret,
            nonce,
          )
          .catch(() => {});
      }
    }
  }

  function resetDiscoveryPreview() {
    generation.current++;
    releasePendingDraftRefs();
    setSessionAuthBusy(false);
    setMode(null); setDiscoveryId(null); setDiscoveryResult(null); setSelectedCandidate(null);
    setGuidedFieldValues({}); setSampleInput(DEFAULT_SAMPLE_INPUT); setDiscoveryEndpoint(null); setDiscoveryProtocol(null);
    setHeaderRows([]); setAuthMode('none'); setApiKeyHeaderName('X-API-Key'); setSessionSecretInput(''); setSessionCredStatus(null); setSessionAuthError('');
    setChecked(false); setQuickProbe(null); setQuickConfirmed(false); setQuickError(''); setMessage(''); setError('');
  }

  function start(which: 'create' | 'edit', profile: TargetPreset | undefined = target, renameTo?: string) {
    if (which === 'edit' && !profile) return;
    generation.current++;
    releasePendingDraftRefs();
    setSessionAuthBusy(false);
    setDiscovering(false); onDiscoveryFlowChange?.(false); setMode(which); setDiscoveryId(null);
    setSelectedCandidate(null); setGuidedFieldValues({}); setSampleInput(DEFAULT_SAMPLE_INPUT);
    setDiscoveryEndpoint(null); setDiscoveryProtocol(null); setChecked(false); setConfirmed(false); setMessage(''); setError('');
    setSessionSecretInput(''); setSessionCredStatus(null); setSessionAuthError('');
    if (which === 'create') setProbe(null);
    setQuickProbe(null);
    setEditingOriginal(which === 'edit' ? profile! : null); setPlatformConfirmed(false);
    setExpected(which === 'edit' ? profile!.profile_revision : null);
    // Preserve legacy server-side credential_alias by omitting it from legacy edit payloads;
    // only http-json managed profiles submit credential_alias or session_auth explicitly.
    const nextForm: ManagedProfile = which === 'edit' ? {
      id: profile!.id, name: renameTo ?? profile!.name, platform_id: profile!.platform_id ?? '',
      platform_name: profile!.platform_name ?? '', endpoint: profile!.endpoint, protocol: profile!.protocol,
      model: profile!.protocol === 'http-json' ? (profile!.default_model || null) : profile!.default_model,
      timeout_seconds: profile!.timeout_default,
      ...(profile!.protocol === 'http-json' && profile!.credential_alias ? { credential_alias: profile!.credential_alias } : {}),
      ...(profile!.protocol === 'http-json' && profile!.session_auth ? { session_auth: profile!.session_auth } : {}),
      ...(profile!.http_config ? { http_config: profile!.http_config } : {}),
      ...(profile!.capability_states ? { capability_states: profile!.capability_states } : {}),
    } : empty;
    setForm(nextForm);
    setBodyJson(JSON.stringify((nextForm.http_config ?? defaultHttpConfig).body_template, null, 2));
    setBodyJsonError('');
    setHeaderRows(headersObjectToRows(nextForm.http_config?.headers));
    if (nextForm.session_auth) {
      setAuthMode(nextForm.session_auth.auth_type === 'api_key' ? 'api_key' : 'bearer');
      setApiKeyHeaderName(nextForm.session_auth.auth_type === 'api_key' ? nextForm.session_auth.header_name : 'X-API-Key');
    } else if (nextForm.credential_alias) {
      setAuthMode('existing');
      setApiKeyHeaderName('X-API-Key');
    } else {
      setAuthMode('none');
      setApiKeyHeaderName('X-API-Key');
    }
    if (which === 'edit' && profile!.id !== target?.id) onChanged(profile!.id);
  }

  function change<K extends keyof ManagedProfile>(key: K, v: ManagedProfile[K], preserveSample = false) {
    const token = ++generation.current; setBusy(false);
    let updated = { ...form, [key]: v };
    if (key === 'protocol') {
      if (v === 'http-json') {
        const hc = form.http_config ?? defaultHttpConfig;
        updated = { ...updated, model: form.model || null, http_config: hc };
        setBodyJson(JSON.stringify(hc.body_template, null, 2)); setBodyJsonError('');
        setHeaderRows(headersObjectToRows(hc.headers));
      } else {
        releasePendingDraftRefs();
        const { http_config: _drop, session_auth: _dropSess, ...rest } = updated;
        updated = { ...rest, model: form.model ?? '', timeout_seconds: Math.min(60, updated.timeout_seconds || 30) };
        setHeaderRows([]); setAuthMode('none'); setSessionSecretInput(''); setSessionCredStatus(null); setSessionAuthError('');
      }
    }
    if ((key === 'endpoint' || (key === 'id' && !discoveryId)) && form.session_auth) {
      // Destination origin or draft scope changed; release any draft credential and require re-applying.
      releasePendingDraftRefs();
      updated = { ...updated, session_auth: null };
      setSessionCredStatus(null);
    }
    setForm(updated); setChecked(false); setError('');
    if (key === 'platform_id' || key === 'platform_name') setPlatformConfirmed(false);
    if (['name', 'platform_id', 'platform_name'].includes(key)) { if (discoveryId) void validateForSave(updated, token); return; }
    if (!preserveSample) {
      setQuickProbe(null); setQuickConfirmed(false); setQuickError('');
    }
  }

  function updateHttpConfig(mutator: (prev: HttpContractConfig) => HttpContractConfig, responseOnlyEdit = false) {
    const prev = form.http_config ?? defaultHttpConfig;
    const next = mutator(prev);
    // Editing only response-mapping fields preserves an existing bounded response_sample
    // so revised mappings can be checked locally without sending another POST, while
    // still invalidating "verified" status if the previous probe was marked succeeded.
    const keepSample = responseOnlyEdit && Boolean(quickProbe?.response_sample);
    if (keepSample && quickProbe && quickProbe.connection_status === 'succeeded') {
      setQuickProbe({
        ...quickProbe,
        connection_status: 'incompatible',
        runtime_protocol_compatible: false,
        verification_state: 'response_mapping_unresolved',
        extracted_output: null,
        guidance: 'Response mapping changed. Review local validation against the captured response sample or run a fresh connection test.',
      });
    }
    const token = ++generation.current; setBusy(false);
    const updated: ManagedProfile = { ...form, http_config: next };
    setForm(updated); setChecked(false); setError(''); setQuickConfirmed(false);
    if (!keepSample) { setQuickProbe(null); setQuickError(''); }
    void token;
  }

  function updateCapability(capKey: string, state: CapabilityState | '') {
    const prev = { ...(form.capability_states ?? {}) };
    if (!state) { delete prev[capKey]; } else { prev[capKey] = state; }
    change('capability_states', Object.keys(prev).length ? prev : null);
  }

  function updateHeaderRows(nextRows: HeaderRow[]) {
    setHeaderRows(nextRows);
    const validated = validateHeaderRows(nextRows, form.session_auth);
    if (!validated.error) {
      updateHttpConfig(prev => ({ ...prev, headers: validated.headers }));
    } else {
      setChecked(false); setQuickConfirmed(false); setQuickProbe(null); setQuickError('');
    }
  }

  function switchAuthMode(nextMode: AuthUiMode) {
    generation.current++;
    setAuthMode(nextMode);
    setSessionAuthError('');
    setSessionSecretInput('');
    setChecked(false); setQuickConfirmed(false); setQuickProbe(null); setQuickError('');
    if (nextMode === 'none') {
      releasePendingDraftRefs();
      setSessionCredStatus(null);
      setForm(prev => ({ ...prev, credential_alias: null, session_auth: null }));
    } else if (nextMode === 'existing') {
      releasePendingDraftRefs();
      setSessionCredStatus(null);
      setForm(prev => ({ ...prev, session_auth: null }));
    } else if (nextMode === 'bearer') {
      const keepRef = form.session_auth?.auth_type === 'bearer' ? form.session_auth.ref_id : undefined;
      releasePendingDraftRefs(keepRef);
      if (!keepRef) setSessionCredStatus(null);
      setForm(prev => ({
        ...prev,
        credential_alias: null,
        session_auth: prev.session_auth?.auth_type === 'bearer' ? prev.session_auth : null,
      }));
    } else if (nextMode === 'api_key') {
      const keepRef = form.session_auth?.auth_type === 'api_key' ? form.session_auth.ref_id : undefined;
      releasePendingDraftRefs(keepRef);
      if (!keepRef) setSessionCredStatus(null);
      setForm(prev => ({
        ...prev,
        credential_alias: null,
        session_auth: prev.session_auth?.auth_type === 'api_key' ? prev.session_auth : null,
      }));
    }
  }

  function changeApiKeyHeaderName(nextHeader: string) {
    setApiKeyHeaderName(nextHeader);
    setSessionAuthError('');
    setChecked(false); setQuickConfirmed(false); setQuickProbe(null); setQuickError('');
    if (
      form.session_auth?.auth_type === 'api_key' &&
      form.session_auth.header_name.toLowerCase() !== nextHeader.trim().toLowerCase()
    ) {
      releasePendingDraftRefs();
      setSessionCredStatus(null);
      setForm(prev => ({ ...prev, session_auth: null }));
    }
  }

  function routeAuthHeaderToControl(rowId: string, headerName: string) {
    const remaining = headerRows.filter(r => r.id !== rowId);
    updateHeaderRows(remaining);
    const low = headerName.toLowerCase();
    if (low === 'authorization') {
      switchAuthMode('bearer');
    } else {
      const safeHeader = DISALLOWED_API_KEY_HEADERS.has(low) ? 'X-API-Key' : headerName;
      changeApiKeyHeaderName(safeHeader);
      switchAuthMode('api_key');
    }
  }

  async function applyDraftSessionCredential() {
    if (sessionAuthBusy || !form.endpoint.trim()) return;
    if (!sessionSecretInput.trim()) {
      setSessionAuthError('Enter a credential value before applying.');
      return;
    }
    const resolvedHeader = authMode === 'api_key' ? apiKeyHeaderName.trim() : 'Authorization';
    if (authMode === 'api_key') {
      if (!API_KEY_HEADER_NAME_RE.test(resolvedHeader) || DISALLOWED_API_KEY_HEADERS.has(resolvedHeader.toLowerCase())) {
        setSessionAuthError(`Header "${resolvedHeader || '(empty)'}" is not a valid API key header name.`);
        return;
      }
      if (headerRows.some(r => r.key.trim().toLowerCase() === resolvedHeader.toLowerCase())) {
        setSessionAuthError(`Remove the conflicting custom header "${resolvedHeader}" before applying this API key header.`);
        return;
      }
    }
    const opId = ++sessionOpId.current;
    const token = ++generation.current;
    const scopeKind: 'discovery' | 'draft' = discoveryId ? 'discovery' : 'draft';
    const scopeId = discoveryId ?? (form.id.trim() || 'draft-http-target');
    // Only reuse an existing ref_id if it is a pending draft/discovery ref created in this
    // same scope — NEVER pass a saved target-scoped ref_id under draft or discovery scope.
    const currentRef = form.session_auth?.ref_id;
    const currentDraftScope = currentRef ? pendingDraftRefs.current.get(currentRef) : undefined;
    const reusableDraftRef =
      currentRef &&
      currentDraftScope &&
      currentDraftScope.scope_kind === scopeKind &&
      currentDraftScope.scope_id === scopeId &&
      form.session_auth?.auth_type === authMode
        ? currentRef
        : undefined;
    setSessionAuthBusy(true); setSessionAuthError(''); setError('');
    try {
      const meta = await testingApi.setSessionCredential(
        {
          scope_kind: scopeKind,
          scope_id: scopeId,
          endpoint: form.endpoint.trim(),
          auth_type: authMode === 'api_key' ? 'api_key' : 'bearer',
          header_name: resolvedHeader,
          secret_value: sessionSecretInput,
          ...(reusableDraftRef ? { ref_id: reusableDraftRef } : {}),
        },
        secret,
        nonce,
      );
      if (token !== generation.current) {
        // Stale async response for a superseded form state: release the orphaned draft credential.
        void testingApi
          .clearSessionCredential(
            { ref_id: meta.ref_id, scope_kind: scopeKind, scope_id: scopeId },
            secret,
            nonce,
          )
          .catch(() => {});
        return;
      }
      pendingDraftRefs.current.set(meta.ref_id, { scope_kind: scopeKind, scope_id: scopeId });
      releasePendingDraftRefs(meta.ref_id);
      setSessionSecretInput('');
      setSessionCredStatus(meta);
      const nextSessionAuth: SessionAuthReference = {
        ref_id: meta.ref_id,
        auth_type: meta.auth_type,
        header_name: meta.header_name,
      };
      setForm(prev => ({ ...prev, credential_alias: null, session_auth: nextSessionAuth }));
      setChecked(false); setQuickConfirmed(false); setQuickProbe(null); setQuickError('');
    } catch (e) {
      if (token === generation.current) {
        setSessionAuthError(e instanceof Error ? e.message : 'Session credential could not be stored.');
      }
    } finally {
      if (opId === sessionOpId.current) setSessionAuthBusy(false);
    }
  }

  async function clearDraftSessionCredential() {
    if (sessionAuthBusy) return;
    const refId = form.session_auth?.ref_id ?? sessionCredStatus?.ref_id;
    const ownedDraftScope = refId ? pendingDraftRefs.current.get(refId) : undefined;
    const opId = ++sessionOpId.current;
    const token = ++generation.current;
    setSessionAuthBusy(true); setSessionAuthError('');
    try {
      // Only clear credentials created for this unsaved draft/discovery session.
      // Never delete a saved target's live credential until the operator explicitly saves the edit
      // or clicks Clear Session Credential on the saved Target summary card.
      if (refId && ownedDraftScope) {
        await testingApi.clearSessionCredential(
          {
            ref_id: refId,
            scope_kind: ownedDraftScope.scope_kind,
            scope_id: ownedDraftScope.scope_id,
          },
          secret,
          nonce,
        );
        pendingDraftRefs.current.delete(refId);
      }
      if (token !== generation.current) return;
      setSessionSecretInput('');
      setSessionCredStatus(null);
      setForm(prev => ({ ...prev, session_auth: null }));
      setChecked(false); setQuickConfirmed(false); setQuickProbe(null); setQuickError('');
    } catch (e) {
      if (token === generation.current) {
        setSessionAuthError(e instanceof Error ? e.message : 'Session credential could not be cleared.');
      }
    } finally {
      if (opId === sessionOpId.current) setSessionAuthBusy(false);
    }
  }

  async function updateSavedSessionCredential() {
    if (!target || !target.session_auth || savedSessionBusy || !savedSessionInput.trim()) return;
    const opId = ++savedSessionOpId.current;
    const token = ++generation.current;
    setSavedSessionBusy(true); setSavedSessionMessage(''); setError('');
    try {
      await testingApi.setSessionCredential(
        {
          scope_kind: 'target',
          scope_id: target.id,
          endpoint: target.endpoint,
          auth_type: target.session_auth.auth_type,
          header_name: target.session_auth.header_name,
          secret_value: savedSessionInput,
          ref_id: target.session_auth.ref_id,
        },
        secret,
        nonce,
      );
      if (token !== generation.current) return;
      setSavedSessionInput('');
      setConfirmed(false);
      setProbe(null);
      setSavedSessionMessage('Session credential updated in Backend memory. Previous connection verification was cleared; run Test Connection to verify.');
      onChanged(target.id);
    } catch (e) {
      if (token === generation.current) {
        setError(e instanceof Error ? e.message : 'Session credential update was rejected.');
      }
    } finally {
      if (opId === savedSessionOpId.current) setSavedSessionBusy(false);
    }
  }

  async function clearSavedSessionCredential() {
    if (!target || !target.session_auth || savedSessionBusy) return;
    const opId = ++savedSessionOpId.current;
    const token = ++generation.current;
    setSavedSessionBusy(true); setSavedSessionMessage(''); setError('');
    try {
      await testingApi.clearSessionCredential(
        { ref_id: target.session_auth.ref_id, target_id: target.id },
        secret,
        nonce,
      );
      if (token !== generation.current) return;
      setSavedSessionInput('');
      setConfirmed(false);
      setProbe(null);
      setSavedSessionMessage('Session credential cleared from Backend memory. Supply it again before running Test Connection or security scans.');
      onChanged(target.id);
    } catch (e) {
      if (token === generation.current) {
        setError(e instanceof Error ? e.message : 'Session credential could not be cleared.');
      }
    } finally {
      if (opId === savedSessionOpId.current) setSavedSessionBusy(false);
    }
  }

  const headerValidation = form.protocol === 'http-json'
    ? validateHeaderRows(headerRows, form.session_auth)
    : { error: '', authHeaderHint: null, headers: {} };
  const headerError = headerValidation.error;
  const discoveryBindingValid = !discoveryId || (form.endpoint === discoveryEndpoint && form.protocol === discoveryProtocol);
  const formSig = httpContractSignature(form.endpoint, form.protocol, form.credential_alias, form.http_config, form.session_auth);
  const existingEndpoint = mode === 'create' ? existingProfiles.find(item => httpContractSignature(item.endpoint, item.protocol, item.credential_alias, item.http_config, item.session_auth) === formSig) : undefined;
  const hasUnresolvedFields = form.protocol === 'http-json' && hasUnresolvedPlaceholder(form.http_config?.body_template);
  const textPathMissing = form.protocol === 'http-json' && !(form.http_config?.response?.text_path?.trim());
  const authSchemeUnsupported = form.protocol === 'http-json' && !!discoveryId && selectedCandidate?.requires_auth === true && selectedCandidate?.auth_scheme_supported === false;
  const hasConfiguredAuth = Boolean(form.credential_alias || form.session_auth);
  const missingDiscoveredAuth = form.protocol === 'http-json' && !!discoveryId && selectedCandidate?.requires_auth === true && !authSchemeUnsupported && !hasConfiguredAuth;
  const pendingSessionCredential = form.protocol === 'http-json' && (authMode === 'bearer' || authMode === 'api_key') && !form.session_auth;
  const discoveryAuthBlocked = authSchemeUnsupported || missingDiscoveredAuth;
  // Separate request/sample-probe readiness from full response-mapping / save readiness!
  // For http-json, a bounded sample probe is allowed when request contract + auth are resolved,
  // even when response text_path is still unresolved (avoids response-mapping discovery deadlock).
  const probeInputReady = form.protocol === 'http-json'
    ? (!hasUnresolvedFields && !bodyJsonError && !headerError && !discoveryAuthBlocked && !pendingSessionCredential && !!form.endpoint.trim())
    : !!form.model;
  const saveContractReady = form.protocol === 'http-json'
    ? (!hasUnresolvedFields && !bodyJsonError && !headerError && !discoveryAuthBlocked && !pendingSessionCredential && !textPathMissing)
    : !!form.model;
  const authBadge = authStatusLabel(selectedCandidate);
  const statusPathUnconfirmed = form.protocol === 'http-json'
    && Boolean(form.http_config?.response?.status_path?.trim())
    && !(form.http_config?.response?.complete_status_values?.length)
    && !(form.http_config?.response?.incomplete_status_values?.length);
  const advancedHttpOpenByDefault = form.protocol === 'http-json' && Boolean(bodyJsonError);
  const platformChanged = mode === 'edit' && !!editingOriginal && (editingOriginal.platform_id !== form.platform_id || editingOriginal.platform_name !== form.platform_name);
  const discoveredPlatformChanged = mode === 'create' && !!discoveryId && !!discoveryResult?.proposed_profile &&
    (discoveryResult.proposed_profile.platform_id !== form.platform_id || discoveryResult.proposed_profile.platform_name !== form.platform_name);
  const platformNeedsConfirmation = platformChanged || discoveredPlatformChanged;
  const knownPlatforms = Array.from(new Map(existingProfiles.filter(item => item.platform_id && item.platform_name)
    .map(item => [item.platform_id!, item.platform_name!])).entries());

  function choosePlatform(id: string) {
    const value = id === 'unknown' ? ['unknown', 'Unknown'] :
      knownPlatforms.find(([key]) => key === id) ?? [form.platform_id, form.platform_name];
    const updated = { ...form, platform_id: value[0], platform_name: value[1] }; setForm(updated); setChecked(false); setPlatformConfirmed(false);
    if (discoveryId) { const token = ++generation.current; void validateForSave(updated, token); }
  }

  const matchingProfiles = existingProfiles.filter(item => `${item.name} ${item.endpoint} ${item.platform_name ?? ''}`.toLowerCase().includes(query.trim().toLowerCase()));
  const platformGroups = Array.from(new Map(matchingProfiles.map(item => [item.platform_id ?? 'unknown', item.platform_name ?? 'Unknown platform'])).entries());

  async function deleteTargetPermanently() {
    if (!deleteCandidate || busy) return;
    const candidate = deleteCandidate;
    const token = ++generation.current; setBusy(true); setError('');
    try {
      await testingApi.deleteTarget({ target_id: candidate.id, profile_revision: candidate.profile_revision }, secret, nonce);
      if (token !== generation.current) return;
      setDeleteCandidate(null);
      const msg = `Target "${candidate.name}" (${candidate.id}) and its associated target data were permanently deleted.`;
      carryMessage.current = msg;
      setMessage(msg);
      onChanged(candidate.id === target?.id ? '' : target?.id ?? '');
    } catch (e) {
      if (token === generation.current) setError(e instanceof Error ? e.message : 'Delete rejected. Check if a scan is currently running and reload targets.');
    } finally { if (token === generation.current) setBusy(false); }
  }

  function probeError(e: unknown) {
    return e instanceof Error && e.message.startsWith('Workflow API') ? e.message :
      'Connection could not be verified. Check the endpoint and retry the benign probe.';
  }

  async function validateForSave(profile: ManagedProfile, token: number) {
    if (existingTargetIds.includes(profile.id)) {
      setError('Target identifier already exists. Select the existing target, or change Target identifier under Advanced target fields before saving a new profile.');
      return;
    }
    const sig = httpContractSignature(profile.endpoint, profile.protocol, profile.credential_alias, profile.http_config, profile.session_auth);
    if (existingProfiles.some(item => profile.protocol === 'http-json' ? httpContractSignature(item.endpoint, item.protocol, item.credential_alias, item.http_config, item.session_auth) === sig : item.endpoint === profile.endpoint && item.protocol === profile.protocol && item.default_model === profile.model)) {
      setError(profile.protocol === 'http-json' ? 'This target invocation contract is already saved. Select the existing target or customize its request contract.' : 'This endpoint, protocol and model are already saved. Select the existing target instead of creating a duplicate.');
      return;
    }
    if (profile.protocol === 'http-json' && hasUnresolvedPlaceholder(profile.http_config?.body_template)) {
      setChecked(false);
      setError('Resolve all required discovery parameters before validating or saving.');
      return;
    }
    if (profile.protocol === 'http-json' && !(profile.http_config?.response?.text_path?.trim())) {
      setChecked(false);
      setError('Configure or confirm a response text path before validating or saving.');
      return;
    }
    if (profile.protocol === 'http-json' && discoveryId && selectedCandidate?.requires_auth === true) {
      if (selectedCandidate.auth_scheme_supported === false) {
        setChecked(false);
        setError('Discovered operation requires an authentication scheme not supported by server-managed Bearer credential aliases or session header credentials.');
        return;
      }
      if (!profile.credential_alias && !profile.session_auth) {
        setChecked(false);
        setError('Discovered operation requires authentication. Configure Bearer Token, API Key Header, or Existing Credential before validating or saving.');
        return;
      }
    }
    try {
      await (discoveryId && profile.protocol === 'http-json'
        ? testingApi.validateManaged(profile, null, secret, nonce, discoveryId)
        : testingApi.validateManaged(profile, null, secret, nonce));
      if (token === generation.current) setChecked(true);
    } catch (e) { if (token === generation.current) setError(probeError(e)); }
  }

  async function acceptDiscovery(profile: ManagedProfile, id: string, result: DiscoveryResult, candidate?: OpenApiCandidate) {
    const token = ++generation.current;
    releasePendingDraftRefs();
    setSessionAuthBusy(false);
    setMode('create'); setForm(profile); setExpected(null); setChecked(false); setDiscoveryId(id); setDiscoveryResult(result);
    setSelectedCandidate(candidate ?? null);
    setGuidedFieldValues({});
    setSampleInput(DEFAULT_SAMPLE_INPUT);
    setDiscoveryEndpoint(profile.endpoint); setDiscoveryProtocol(profile.protocol);
    setBodyJson(JSON.stringify((profile.http_config ?? defaultHttpConfig).body_template, null, 2));
    setBodyJsonError('');
    setHeaderRows(headersObjectToRows(profile.http_config?.headers));
    setSessionSecretInput(''); setSessionCredStatus(null); setSessionAuthError('');
    if (profile.protocol === 'http-json') {
      const discApiHdr = discoveredApiKeyHeader(candidate);
      if (profile.session_auth) {
        setAuthMode(profile.session_auth.auth_type === 'api_key' ? 'api_key' : 'bearer');
        setApiKeyHeaderName(profile.session_auth.auth_type === 'api_key' ? profile.session_auth.header_name : 'X-API-Key');
      } else if (profile.credential_alias) {
        setAuthMode('existing');
        setApiKeyHeaderName('X-API-Key');
      } else if (candidate?.requires_auth) {
        if (credentialAliases.length > 0) {
          setAuthMode('existing');
          setApiKeyHeaderName('X-API-Key');
        } else if (discApiHdr) {
          setAuthMode('api_key');
          setApiKeyHeaderName(discApiHdr);
        } else {
          setAuthMode('bearer');
          setApiKeyHeaderName('X-API-Key');
        }
      } else {
        setAuthMode('none');
        setApiKeyHeaderName(discApiHdr ?? 'X-API-Key');
      }
    } else {
      setAuthMode('none');
      setApiKeyHeaderName('X-API-Key');
    }
    setQuickProbe(null); setQuickConfirmed(false); setQuickError(''); setError('');
    if (profile.protocol === 'http-json') {
      const authPending = candidate?.requires_auth === true && (candidate.auth_scheme_supported === false || (!profile.credential_alias && !profile.session_auth));
      const textReady = Boolean(profile.http_config?.response?.text_path?.trim());
      if (!hasUnresolvedPlaceholder(profile.http_config?.body_template) && !authPending && textReady) {
        await validateForSave(profile, token);
      }
      return;
    }
    if (!profile.model) return;
    setBusy(true);
    try {
      const probeRes = await testingApi.probeDiscovery(profile, id, secret, nonce);
      if (token === generation.current) setQuickProbe(probeRes);
    } catch (e) { if (token === generation.current) setQuickError(probeError(e)); }
    if (token === generation.current) await validateForSave(profile, token);
    if (token === generation.current) setBusy(false);
  }

  async function validate() {
    const token = generation.current; setBusy(true); setError(''); setMessage('');
    try {
      await (discoveryId && form.protocol === 'http-json'
        ? testingApi.validateManaged(form, expected, secret, nonce, discoveryId)
        : testingApi.validateManaged(form, expected, secret, nonce));
      if (token !== generation.current) return;
      setChecked(true);
      setMessage('Target details are valid. Save to create an unreviewed profile.');
    } catch (e) {
      if (token !== generation.current) return;
      setChecked(false);
      setError(e instanceof Error && e.message.startsWith('Workflow API')
        ? e.message
        : 'Target details are invalid or stale. Check the identifier, endpoint, configuration, timeout and current revision.');
    } finally { if (token === generation.current) setBusy(false); }
  }

  const effectiveSampleInput = sampleInput.trim() || DEFAULT_SAMPLE_INPUT;

  async function probeQuick() {
    if (!discoveryId || !discoveryBindingValid || !quickConfirmed || busy || !probeInputReady || !enabled || !(localSingleUser || unlocked)) return;
    const token = generation.current; setBusy(true); setQuickProbe(null); setQuickError(''); setChecked(false);
    try {
      const probeRes = form.protocol === 'http-json'
        ? await testingApi.probeDiscovery(form, discoveryId, secret, nonce, effectiveSampleInput)
        : await testingApi.probeDiscovery(form, discoveryId, secret, nonce);
      if (token !== generation.current) return;
      setQuickProbe(probeRes); setQuickConfirmed(false);
    } catch (e) {
      if (token === generation.current) { setQuickError(probeError(e)); setQuickConfirmed(false); }
    }
    if (token === generation.current && saveContractReady) await validateForSave(form, token);
    if (token === generation.current) setBusy(false);
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!checked || busy || !discoveryBindingValid) return;
    const token = generation.current; setBusy(true); setError('');
    try {
      const wasDiscovered = !!discoveryId;
      const row = await (discoveryId
        ? testingApi.saveManaged(form, expected, secret, nonce, discoveryId, !!discoveredPlatformChanged && platformConfirmed)
        : platformChanged
          ? testingApi.saveManaged(form, expected, secret, nonce, undefined, platformConfirmed)
          : testingApi.saveManaged(form, expected, secret, nonce));
      if (token !== generation.current) return;
      // Release any other abandoned pending draft credentials; the saved ref now belongs to the target.
      releasePendingDraftRefs(row.session_auth?.ref_id ?? undefined);
      pendingDraftRefs.current.clear();
      setSessionCredStatus(null);
      setSessionAuthBusy(false);
      if (wasDiscovered && row.id === form.id && row.endpoint === form.endpoint && row.protocol === form.protocol &&
        (row.default_model || null) === (form.model || null) && row.timeout_default === form.timeout_seconds) {
        carryProbe.current = { id: row.id, revision: row.profile_revision, result: quickProbe };
      }
      setAwaitingSelection(!(mode === 'edit' && row.profile_revision === target?.profile_revision));
      setMode(null); setDiscovering(false); setDiscoveryId(null); setDiscoveryProtocol(null); setChecked(false);
      setMessage('Target saved without review or security execution permission. Review this exact profile before testcase selection.');
      onDiscoveryFlowChange?.(false); onChanged(row.id);
    } catch {
      if (token === generation.current) setError('Configuration could not be saved. Reload the catalog and check the profile.');
    } finally { if (token === generation.current) setBusy(false); }
  }

  async function review() {
    if (!target || !confirmed || busy) return;
    const token = generation.current; setBusy(true); setError('');
    try {
      const row = await testingApi.reviewManaged(target, secret, nonce);
      if (token !== generation.current) return;
      setConfirmed(false);
      setMessage('Review saved for this exact profile revision and policy. A separate execution grant is still required.');
      onChanged(row.id);
    } catch {
      if (token !== generation.current) return;
      setError('Review was rejected. Reload the target and confirm its current endpoint and policy.');
    } finally { if (token === generation.current) setBusy(false); }
  }

  const probeAvailable = !!target && ['supported', 'requires_confirmation'].includes(target.connection_probe.status);
  const probeConfirmationRequired = probeAvailable;

  async function testConnection() {
    if (!target || !probeAvailable || !enabled || !(localSingleUser || unlocked) || !settingsMatch || configurationInvalid || busy || !confirmed) return;
    const first = target.connection_probe.status === 'requires_confirmation', token = generation.current;
    // Generic HTTP JSON probes always require explicit per-probe confirmation and exact endpoint binding,
    // including for already-reviewed profiles.
    const sendExplicitConfirm = target.protocol === 'http-json' || first;
    setProbeKey(identity + nonce); setBusy(true); setChecking(true); setError(''); setProbe(null); setProbeFailed(false);
    try {
      const result = target.protocol === 'http-json'
        ? await testingApi.probe(target, secret, nonce, sendExplicitConfirm, effectiveSampleInput)
        : await testingApi.probe(target, secret, nonce, sendExplicitConfirm);
      if (token !== generation.current) return;
      setProbe(result); setConfirmed(false); onChanged(target.id);
    } catch {
      if (token === generation.current) { setProbeFailed(true); setConfirmed(false); setError('Connection check failed. Check the endpoint and try again.'); }
    } finally { if (token === generation.current) { setBusy(false); setChecking(false); } }
  }

  const webLabReview = localSingleUser && (target?.id === 'dvaa-researchbot-web-lab' || target?.id === 'dvaa-toolbot-lab');
  const maxTimeoutForForm = form.protocol === 'http-json' ? 600 : 60;

  function renderHeadersSection() {
    return (
      <div className="headers-editor full-span" role="region" aria-label="HTTP headers">
        <div className="headers-editor-head">
          <strong>HTTP Headers</strong>
          <button
            type="button"
            disabled={busy || headerRows.length >= 16}
            onClick={() => updateHeaderRows([...headerRows, { id: `hdr-${nextHeaderRowId++}`, key: '', value: '' }])}
          >
            Add Header
          </button>
        </div>
        <div className="header-row header-row-default">
          <span><code>Content-Type</code></span>
          <span><code>application/json</code></span>
          <span className="caption">Default</span>
        </div>
        {headerRows.map((row, idx) => (
          <div className="header-row" key={row.id}>
            <input
              aria-label={`Header name ${idx + 1}`}
              placeholder="e.g. X-Tenant-Id"
              maxLength={64}
              value={row.key}
              onChange={e => updateHeaderRows(headerRows.map(r => (r.id === row.id ? { ...r, key: e.target.value } : r)))}
            />
            <input
              aria-label={`Header value ${idx + 1}`}
              placeholder="Non-secret header value"
              maxLength={256}
              value={row.value}
              onChange={e => updateHeaderRows(headerRows.map(r => (r.id === row.id ? { ...r, value: e.target.value } : r)))}
            />
            <button
              type="button"
              onClick={() => updateHeaderRows(headerRows.filter(r => r.id !== row.id))}
            >
              Remove Header
            </button>
          </div>
        ))}
        <p className="caption">Add non-secret HTTP headers only. Authentication headers belong in the Authentication control below.</p>
        {headerError && (
          <div role="alert" className="notice error">
            <span>{headerError}</span>
            {headerValidation.authHeaderHint && (
              <button
                type="button"
                onClick={() => routeAuthHeaderToControl(headerValidation.authHeaderHint!.rowId, headerValidation.authHeaderHint!.headerName)}
              >
                Use Authentication control
              </button>
            )}
          </div>
        )}
      </div>
    );
  }

  function renderAuthenticationSection() {
    const aliasOptions = Array.from(new Set([
      ...credentialAliases,
      ...(form.credential_alias ? [form.credential_alias] : []),
    ]));
    const activeSessionMatch = Boolean(form.session_auth && form.session_auth.auth_type === authMode);
    const isPendingDraftCred = Boolean(
      activeSessionMatch &&
      form.session_auth &&
      (pendingDraftRefs.current.has(form.session_auth.ref_id) || sessionCredStatus?.ref_id === form.session_auth.ref_id),
    );
    const isSavedTargetCred = Boolean(
      activeSessionMatch &&
      !isPendingDraftCred &&
      mode === 'edit' &&
      editingOriginal?.session_auth &&
      form.session_auth?.ref_id === editingOriginal.session_auth.ref_id,
    );
    const savedTargetCredAvailable = isSavedTargetCred && editingOriginal?.credential_availability === 'available';
    return (
      <div className="auth-control-card full-span" role="region" aria-label="Target authentication">
        <div className="auth-control-head">
          <strong>Authentication</strong>
          {activeSessionMatch && isPendingDraftCred && (
            <span className="auth-availability-pill is-available">
              {mode === 'edit'
                ? `Pending session credential ready (${form.session_auth!.header_name}) — save to apply`
                : `Session credential active (${form.session_auth!.header_name})`}
            </span>
          )}
          {activeSessionMatch && isSavedTargetCred && (
            <span className={`auth-availability-pill ${savedTargetCredAvailable ? 'is-available' : 'is-unavailable'}`}>
              {savedTargetCredAvailable
                ? `Saved session credential active (${form.session_auth!.header_name})`
                : `Saved session credential unavailable (${form.session_auth!.header_name}) — supply again`}
            </span>
          )}
          {authMode === 'existing' && form.credential_alias && (
            <span className={`auth-availability-pill ${credentialAliasAvailability[form.credential_alias] === 'available' ? 'is-available' : 'is-unavailable'}`}>
              Alias: {form.credential_alias} ({credentialAliasAvailability[form.credential_alias] ?? 'configured'})
            </span>
          )}
        </div>
        <label>
          Authentication mode
          <select
            aria-label="Authentication"
            value={authMode}
            onChange={e => switchAuthMode(e.target.value as AuthUiMode)}
          >
            <option value="none">None</option>
            <option value="bearer">Bearer Token</option>
            <option value="api_key">API Key Header</option>
            <option value="existing">Existing Credential</option>
          </select>
        </label>
        {authMode === 'bearer' && <>
          <div className="session-auth-row">
            <label>
              Bearer Token (session memory)
              <input
                type="password"
                autoComplete="off"
                placeholder={activeSessionMatch ? 'Enter new token to replace' : 'Paste Bearer token'}
                value={sessionSecretInput}
                onChange={e => { setSessionSecretInput(e.target.value); setSessionAuthError(''); }}
              />
            </label>
            <button
              type="button"
              disabled={sessionAuthBusy || !sessionSecretInput.trim() || !form.endpoint.trim()}
              onClick={() => void applyDraftSessionCredential()}
            >
              {sessionAuthBusy ? 'Applying...' : activeSessionMatch ? 'Update Session Credential' : 'Apply Session Credential'}
            </button>
            {activeSessionMatch && (
              <button
                type="button"
                disabled={sessionAuthBusy}
                onClick={() => void clearDraftSessionCredential()}
              >
                {isSavedTargetCred ? 'Remove from Draft' : 'Clear Session Credential'}
              </button>
            )}
          </div>
          <p className="caption">
            Stored in Backend memory only for this Target and origin. Session credentials must be supplied again after a Backend restart, while saved Target configurations remain available.
          </p>
        </>}
        {authMode === 'api_key' && <>
          <div className="session-auth-row">
            <label>
              API Key Header Name
              <input
                maxLength={64}
                value={apiKeyHeaderName}
                onChange={e => changeApiKeyHeaderName(e.target.value)}
                placeholder="X-API-Key"
              />
            </label>
            <label>
              API Key Value (session memory)
              <input
                type="password"
                autoComplete="off"
                placeholder={activeSessionMatch ? 'Enter new API key to replace' : 'Paste API key'}
                value={sessionSecretInput}
                onChange={e => { setSessionSecretInput(e.target.value); setSessionAuthError(''); }}
              />
            </label>
            <button
              type="button"
              disabled={sessionAuthBusy || !sessionSecretInput.trim() || !apiKeyHeaderName.trim() || !form.endpoint.trim()}
              onClick={() => void applyDraftSessionCredential()}
            >
              {sessionAuthBusy ? 'Applying...' : activeSessionMatch ? 'Update Session Credential' : 'Apply Session Credential'}
            </button>
            {activeSessionMatch && (
              <button
                type="button"
                disabled={sessionAuthBusy}
                onClick={() => void clearDraftSessionCredential()}
              >
                {isSavedTargetCred ? 'Remove from Draft' : 'Clear Session Credential'}
              </button>
            )}
          </div>
          <p className="caption">
            Stored in Backend memory only for this Target and origin. Session credentials must be supplied again after a Backend restart, while saved Target configurations remain available.
          </p>
        </>}
        {authMode === 'existing' && (
          aliasOptions.length > 0 ? (
            <label>
              Credential alias (server-managed env ref)
              <select
                value={form.credential_alias ?? ''}
                onChange={e => change('credential_alias', e.target.value || null)}
              >
                <option value="">Select registered alias</option>
                {aliasOptions.map(alias => {
                  const avail = credentialAliasAvailability[alias];
                  const suffix = avail === 'available' ? ' (available)' : avail === 'unavailable' ? ' (env var not set)' : '';
                  return <option key={alias} value={alias}>{alias}{suffix}</option>;
                })}
              </select>
            </label>
          ) : (
            <div className="notice" role="note">
              <strong>No credential aliases registered</strong>
              <p className="caption">
                Switch to Bearer Token or API Key Header above for Backend session memory authentication, or register a server-managed env alias in your Target catalog JSON.
              </p>
            </div>
          )
        )}
        {sessionAuthError && <p role="alert">{sessionAuthError}</p>}
      </div>
    );
  }

  const quickProbeWaitingMessage = form.protocol === 'http-json'
    ? (hasUnresolvedFields
      ? 'Resolve required parameters before running the connection test.'
      : headerError
        ? 'Fix HTTP header validation errors before running the connection test.'
        : discoveryAuthBlocked
          ? (authSchemeUnsupported
            ? 'Unsupported authentication scheme for Bearer or API key header authentication.'
            : 'Configure authentication (Bearer Token, API Key Header, or Existing Credential) before running the connection test.')
          : pendingSessionCredential
            ? 'Apply the session credential before running the connection test.'
            : bodyJsonError
              ? 'Fix the request JSON body before running the connection test.'
              : textPathMissing
                ? 'Request contract is ready. Run an authorized sample probe to inspect the response shape and confirm response mapping.'
                : 'No connection probe has been sent.')
    : (!form.model ? 'Enter a model identifier to run the connection check.' : 'No connection probe has been sent.');

  const resolvedPreviewBody = form.protocol === 'http-json' && !bodyJsonError
    ? JSON.stringify(renderTemplatePreview((form.http_config ?? defaultHttpConfig).body_template, effectiveSampleInput), null, 2)
    : null;
  const savedHttpPreviewBody = target?.protocol === 'http-json' && target.http_config
    ? JSON.stringify(renderTemplatePreview(target.http_config.body_template, effectiveSampleInput), null, 2)
    : null;

  return <div className="target-management" aria-label="Target management">
    {!enabled && existingSelector}
    {enabled && (!(localSingleUser || unlocked) ? <div className="target-unlock"><label>Operator secret <input type="password" autoComplete="off" value={secret} onChange={e => setSecret(e.target.value)} /></label> <button disabled={!secret || !nonce || busy} onClick={unlock}>Unlock target management</button><p className="caption">Local operator access. The secret is not saved.</p></div> : <>
      <div className="target-journeys" role="group" aria-label="Choose target setup"><button className={discovering ? 'is-active' : ''} aria-pressed={discovering} onClick={() => { if (!discovering) { resetDiscoveryPreview(); setDiscovering(true); onDiscoveryFlowChange?.(true); } }} disabled={busy}>Connect new target</button><button className={!discovering ? 'is-active' : ''} aria-pressed={!discovering} onClick={() => { if (discovering) { setDiscovering(false); resetDiscoveryPreview(); onDiscoveryFlowChange?.(false); } }} disabled={busy}>Select existing target</button></div>
      {discovering && <DiscoveryPanel nonce={nonce} secret={secret} onReset={resetDiscoveryPreview} onUse={acceptDiscovery} />}
      {!discovering && <section className="target-list" aria-label="Existing targets"><div className="target-list-head"><div><h2>Existing targets</h2><p className="caption">Select a target directly. Platform is an association, separate from protocol and Target ID.</p></div><button type="button" onClick={() => start('create')} disabled={busy}>Add Target</button></div>
        <label className="target-search">Search targets<input type="search" value={query} onChange={e => setQuery(e.target.value)} placeholder="Name, platform or endpoint" /></label>
        {matchingProfiles.length === 0 ? <p className="target-empty">{existingProfiles.length ? 'No targets match this search.' : 'No active targets. Connect a target.'}</p> : platformGroups.map(([id, name]) => <div className="target-platform-group" key={id}><h3>{name}</h3><div className="target-list-rows">{matchingProfiles.filter(item => (item.platform_id ?? 'unknown') === id).map(item => {
          const active = item.id === target?.id; const itemConnection = active ? connection : item.connection_verification?.status === 'compatible' ? 'Connected' : 'Not checked'; return <div className={`target-list-row ${active ? 'is-selected' : ''}`} key={item.id}>
            <button type="button" className="target-list-select" aria-current={active ? 'true' : undefined} onClick={() => onChanged(item.id)}><strong>{item.name}</strong><span>{item.endpoint}</span><small>{item.protocol === 'mcp-jsonrpc' ? 'MCP' : item.protocol === 'http-json' ? 'HTTP JSON' : 'HTTP chat'} · ID: <code>{item.id}</code> · {item.platform_provenance?.replaceAll('_', ' ') ?? 'platform source unknown'}</small></button>
            <div className="target-row-status"><span>{itemConnection}</span><span>{item.authorization_status === 'reviewed_for_offline_configuration' ? 'Reviewed' : 'Review required'}</span></div>
            <div className="target-row-actions"><button type="button" onClick={() => start('edit', item)} disabled={busy}>Edit</button><button type="button" className="danger-button" onClick={() => { setError(''); setDeleteCandidate(item); }} disabled={busy}>Delete</button></div>
          </div>;
        })}</div></div>)}
        {existingProfiles.length === 0 && target && <button type="button" onClick={() => start('edit')} disabled={busy}>Edit Target</button>}
      </section>}
      {!discovering && !localSingleUser && <button type="button" onClick={() => { generation.current++; setUnlocked(false); setSecret(''); setMode(null); setProbe(null); setConfirmed(false); setDiscovering(false); onDiscoveryFlowChange?.(false); }}>Lock</button>}
      {deleteCandidate && <div className="target-delete-overlay" role="dialog" aria-modal="true" aria-label="Confirm permanent target deletion"><div className="target-delete-dialog">
        <h2>Permanently delete target?</h2>
        <p className="notice error" role="alert"><strong>Warning: This action is permanent and cannot be undone.</strong></p>
        <ul>
          <li><strong>Target Name:</strong> {deleteCandidate.name}</li>
          <li><strong>Target ID:</strong> <code>{deleteCandidate.id}</code></li>
          <li><strong>Endpoint:</strong> <code>{deleteCandidate.endpoint}</code></li>
        </ul>
        <p><strong>The following target-specific records will be permanently purged:</strong></p>
        <ul>
          <li>Target Profile and endpoint/model/protocol configuration</li>
          <li>Application Context / Application Details and security boundaries</li>
          <li>Discovery and connection metadata associated with this Target</li>
          <li>Evidence Source configurations and captures for this Target</li>
          <li>Target-specific security policies, contracts, and MCP bindings</li>
          <li>Scan history, execution results, evidence, and reports bound to this Target</li>
        </ul>
        <p className="caption">Shared testcase datasets, canonical rubrics, and other Targets will not be affected.</p>
        <div className="target-form-actions">
          <button type="button" disabled={busy} onClick={() => setDeleteCandidate(null)}>Cancel</button>
          <button type="button" className="danger-button" disabled={busy} onClick={() => void deleteTargetPermanently()}>{busy ? 'Deleting...' : 'Delete Permanently'}</button>
        </div>
      </div></div>}
      {mode && <form className="target-form" onSubmit={save} aria-label="Manage target details">
        <h3>{discoveryId ? 'Auto-detected Configuration' : mode === 'create' ? 'Add target' : 'Edit target'}</h3>
        {discoveryId && discoveryResult && <p className="target-detected-count">{discoveryResult.advertised_tools.length} advertised tools · {discoveryResult.possible_contracts.length} candidate API contracts. Metadata does not verify tool execution.</p>}
        {mode === 'create' && !discoveryId && !discovering && <button type="button" onClick={() => { setForm(researchBot); setChecked(false); }}>Use DVAA ResearchBot example</button>}
        {mode === 'create' && !discoveryId && !discovering && toolbotLabEnabled && <button type="button" onClick={() => { setForm(toolBotLab); setChecked(false); }}>Use offline ToolBot Lab example</button>}
        <label>Platform association <span className="field-optional">Operator declared</span><select value={knownPlatforms.some(([id]) => id === form.platform_id) || form.platform_id === 'unknown' ? form.platform_id : 'custom'} onChange={e => choosePlatform(e.target.value)}><option value="unknown">Unknown / Local Agent</option>{knownPlatforms.filter(([id]) => id !== 'unknown').map(([id, name]) => <option key={id} value={id}>{name}</option>)}<option value="custom">Custom platform</option></select></label>
        {discoveryId ? <details><summary>Advanced target fields</summary>
          <label>Platform identifier<input value={form.platform_id} required maxLength={128} onChange={e => change('platform_id', e.target.value)} /></label>
          <label>Platform name<input value={form.platform_name} required maxLength={80} onChange={e => change('platform_name', e.target.value)} /></label>
          <label>Target identifier<input value={form.id} required maxLength={128} onChange={e => change('id', e.target.value)} /></label>
          <label>Timeout (seconds)<input type="number" min="1" max={maxTimeoutForForm} step="1" required value={Number.isNaN(form.timeout_seconds) ? '' : form.timeout_seconds} onChange={e => change('timeout_seconds', e.target.valueAsNumber)} /></label>
        </details> : <>
          <label>Platform identifier<input autoFocus value={form.platform_id} required maxLength={128} onChange={e => change('platform_id', e.target.value)} /></label>
          <label>Platform name<input value={form.platform_name} required maxLength={80} onChange={e => change('platform_name', e.target.value)} /></label>
          <label>Target identifier<input value={form.id} required maxLength={128} readOnly={mode === 'edit'} onChange={e => change('id', e.target.value)} /></label>
        </>}
        <label>{discoveryId ? 'Agent Name (from connection step)' : 'Target display name'}<input value={form.name} required maxLength={100} pattern="[A-Za-z0-9 ._-]+" onChange={e => change('name', e.target.value)} /></label>
        {existingEndpoint && <p role="status">Existing target: <strong>{existingEndpoint.name}</strong>. <button type="button" onClick={() => { setDiscovering(false); setMode(null); onDiscoveryFlowChange?.(false); onChanged(existingEndpoint.id); }}>Use {existingEndpoint.name}</button> <button type="button" onClick={() => start('edit', existingEndpoint, form.name.trim() || existingEndpoint.name)}>Rename Existing</button></p>}
        <label>Protocol<select value={form.protocol} onChange={e => change('protocol', e.target.value as ManagedProfile['protocol'])}><option value="openai-chat">HTTP / OpenAI-compatible chat</option><option value="http-json">HTTP / Custom REST JSON</option><option value="mcp-jsonrpc">MCP JSON-RPC</option></select></label>
        <label>Endpoint URL<input type="url" value={form.endpoint} required maxLength={256} onChange={e => change('endpoint', e.target.value)} /></label>
        {form.protocol !== 'http-json' && <label>{form.protocol === 'mcp-jsonrpc' ? 'MCP service identifier (not an LLM model)' : 'Model identifier'}<input value={form.model ?? ''} required maxLength={128} onChange={e => change('model', e.target.value)} /></label>}
        {form.protocol !== 'http-json' && mode === 'edit' && editingOriginal?.credential_alias && <p className="caption">Server-managed credential alias: <code>{editingOriginal.credential_alias}</code> (preserved automatically on save).</p>}
        {form.protocol === 'http-json' && <fieldset className="target-http-contract"><legend>HTTP JSON Contract (uses shared generic_http adapter)</legend>
          <div className="target-contract-summary">
            <span><strong>POST</strong> <code>{form.endpoint || '(endpoint required)'}</code></span>
            <span>Response text: <code>{form.http_config?.response.text_path || 'unresolved'}</code></span>
            <span className={`auth-status-badge ${authBadge.tone}`}>{authBadge.text}</span>
            {form.credential_alias && <span>Alias: <code>{form.credential_alias}</code></span>}
            {form.session_auth && <span>Session auth: <code>{form.session_auth.header_name}</code></span>}
          </div>
          {selectedCandidate && !!selectedCandidate.unresolved_required_field_specs?.length && <div className="notice" role="region" aria-label="Resolve required discovery parameters">
            <strong>Resolve required request parameters</strong>
            <p className="caption">Fill each required field discovered from the API schema. Values preserve JSON types and update the request template.</p>
            {selectedCandidate.unresolved_required_field_specs.map(spec => <label key={spec.name}>Required parameter <code>{spec.name}</code> ({spec.type})
              {spec.enum?.length ? <select value={guidedFieldValues[spec.name] ?? ''} onChange={e => { const raw = e.target.value; setGuidedFieldValues(prev => ({ ...prev, [spec.name]: raw })); if (!raw) return; const typed = coerceTypedValue(raw, spec.type); const nextBody = setNestedField((form.http_config ?? defaultHttpConfig).body_template, spec.name, typed); setBodyJson(JSON.stringify(nextBody, null, 2)); setBodyJsonError(''); updateHttpConfig(prev => ({ ...prev, body_template: nextBody })); }}><option value="">Select value</option>{spec.enum.map(v => <option key={String(v)} value={String(v)}>{String(v)}</option>)}</select> :
                spec.type === 'boolean' ? <select value={guidedFieldValues[spec.name] ?? ''} onChange={e => { const raw = e.target.value; setGuidedFieldValues(prev => ({ ...prev, [spec.name]: raw })); if (!raw) return; const nextBody = setNestedField((form.http_config ?? defaultHttpConfig).body_template, spec.name, raw === 'true'); setBodyJson(JSON.stringify(nextBody, null, 2)); setBodyJsonError(''); updateHttpConfig(prev => ({ ...prev, body_template: nextBody })); }}><option value="">Select true/false</option><option value="true">true</option><option value="false">false</option></select> :
                  <input value={guidedFieldValues[spec.name] ?? ''} placeholder={`Enter ${spec.name} (${spec.type})`} onChange={e => { const raw = e.target.value; setGuidedFieldValues(prev => ({ ...prev, [spec.name]: raw })); const nextVal = raw === '' ? `<REQUIRED:${spec.name}>` : coerceTypedValue(raw, spec.type); const nextBody = setNestedField((form.http_config ?? defaultHttpConfig).body_template, spec.name, nextVal); setBodyJson(JSON.stringify(nextBody, null, 2)); setBodyJsonError(''); updateHttpConfig(prev => ({ ...prev, body_template: nextBody })); }} />}
            </label>)}
          </div>}
          {authSchemeUnsupported && <p role="alert">Discovered operation requires an authentication scheme ({selectedCandidate?.auth_schemes?.join(', ') || 'unsupported'}) not supported by server-managed Bearer credential aliases or session header credentials. This endpoint cannot be validated or saved.</p>}
          {missingDiscoveredAuth && <p role="alert">API specification requires authentication. Configure Bearer Token, API Key Header, or Existing Credential below before validating or saving.</p>}
          {hasUnresolvedFields && <p role="alert">Unresolved required discovery placeholders remain in the request template. Fill them before validating, testing, or saving.</p>}
          {textPathMissing && <p role="status" className="caption">Response text path is unresolved. You can run an authorized sample probe below to inspect the response shape, or enter the response text path in Advanced HTTP configuration before saving.</p>}
          {renderHeadersSection()}
          {renderAuthenticationSection()}
          {statusPathUnconfirmed && <div className="readiness-warning" role="status">Status field <code>{form.http_config?.response.status_path}</code> is configured without confirmed complete/incomplete values. <code>response_complete</code> will stay unknown until confirmed in Advanced HTTP configuration.</div>}
          <details className="target-advanced" open={advancedHttpOpenByDefault}><summary>Advanced HTTP Configuration (JSON template, response mapping &amp; timeout)</summary>
            <label className="full-span">Request JSON body template (must include <code>{'{{input}}'}</code>)<textarea rows={5} value={bodyJson} onChange={e => { const raw = e.target.value; setBodyJson(raw); try { const parsed = JSON.parse(raw); if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw Error('Must be a JSON object.'); setBodyJsonError(''); updateHttpConfig(prev => ({ ...prev, body_template: parsed as Record<string, unknown> })); } catch (err) { setBodyJsonError(err instanceof Error ? err.message : 'Invalid JSON object.'); setChecked(false); } }} /></label>
            {bodyJsonError && <p role="alert">{bodyJsonError}</p>}
            <label>Response text path<input required maxLength={128} value={(form.http_config ?? defaultHttpConfig).response.text_path} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, text_path: e.target.value } }), true)} placeholder="answer" /></label>
            <label>Model identifier (optional)<input maxLength={128} value={form.model ?? ''} onChange={e => change('model', e.target.value.trim() || null)} placeholder="Leave empty if unspecified" /></label>
            <label>Target correlation ID path<input maxLength={128} value={(form.http_config ?? defaultHttpConfig).response.correlation_id_path ?? ''} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, correlation_id_path: e.target.value.trim() || null } }), true)} placeholder="e.g. run_id" /></label>
            <label>Response status path<input maxLength={128} value={(form.http_config ?? defaultHttpConfig).response.status_path ?? ''} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, status_path: e.target.value.trim() || null } }), true)} placeholder="e.g. status" /></label>
            <label>Complete status values (comma-separated)<input maxLength={256} value={((form.http_config ?? defaultHttpConfig).response.complete_status_values ?? []).join(', ')} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, complete_status_values: parseCsvValues(e.target.value) } }), true)} placeholder="e.g. completed, DONE" /></label>
            <label>Incomplete status values (comma-separated)<input maxLength={256} value={((form.http_config ?? defaultHttpConfig).response.incomplete_status_values ?? []).join(', ')} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, incomplete_status_values: parseCsvValues(e.target.value) } }), true)} placeholder="e.g. awaiting_approval, failed" /></label>
            <label>Inline evidence items path<input maxLength={128} value={(form.http_config ?? defaultHttpConfig).response.evidence_mapping?.items ?? ''} onChange={e => { const v = e.target.value.trim(); updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, evidence_mapping: v ? { ...(prev.response.evidence_mapping ?? { items: v }), items: v } : null } }), true); }} placeholder="e.g. steps or events" /></label>
            {(form.http_config ?? defaultHttpConfig).response.evidence_mapping && <>
              <label>Inline action/tool field<input maxLength={128} value={(form.http_config ?? defaultHttpConfig).response.evidence_mapping?.action ?? ''} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, evidence_mapping: { ...(prev.response.evidence_mapping ?? { items: '' }), action: e.target.value.trim() || null } } }), true)} placeholder="e.g. action or operation" /></label>
              <label>Inline arguments field<input maxLength={128} value={(form.http_config ?? defaultHttpConfig).response.evidence_mapping?.arguments ?? ''} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, evidence_mapping: { ...(prev.response.evidence_mapping ?? { items: '' }), arguments: e.target.value.trim() || null } } }), true)} placeholder="e.g. action_input or parameters" /></label>
              <label>Inline decision field<input maxLength={128} value={(form.http_config ?? defaultHttpConfig).response.evidence_mapping?.decision ?? ''} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, evidence_mapping: { ...(prev.response.evidence_mapping ?? { items: '' }), decision: e.target.value.trim() || null } } }), true)} placeholder="e.g. decision" /></label>
              <label>Inline observation/result field<input maxLength={128} value={(form.http_config ?? defaultHttpConfig).response.evidence_mapping?.observation ?? ''} onChange={e => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, evidence_mapping: { ...(prev.response.evidence_mapping ?? { items: '' }), observation: e.target.value.trim() || null } } }), true)} placeholder="e.g. observation or result" /></label>
            </>}
            <label>HTTP request timeout (seconds, 1–600)<input type="number" min="1" max={600} step="1" required value={Number.isNaN(form.timeout_seconds) ? '' : form.timeout_seconds} onChange={e => change('timeout_seconds', e.target.valueAsNumber)} /></label>
          </details>
        </fieldset>}
        <details className="target-advanced"><summary>Target Capability States (optional)</summary>
          <p className="caption">Declare known capabilities per Target profile. Explicitly unsupported execution capabilities block incompatible execution-scoped tests without silent scope downgrade.</p>
          {CAPABILITY_KEYS.map(([capKey, capLabel]) => <label key={capKey}>{capLabel}<select value={form.capability_states?.[capKey] ?? ''} onChange={e => updateCapability(capKey, e.target.value as CapabilityState | '')}><option value="">Default / Unverified</option><option value="supported">Supported</option><option value="unsupported">Unsupported</option><option value="unverified">Unverified</option></select></label>)}
        </details>
        {discoveryId && form.protocol === 'openai-chat' && !form.model && <p role="note">Model not advertised. Enter the model identifier supplied by the target operator before testing the connection.</p>}
        {!discoveryId && form.protocol !== 'http-json' && <label>Timeout (seconds)<input type="number" min="1" max={maxTimeoutForForm} step="1" required value={Number.isNaN(form.timeout_seconds) ? '' : form.timeout_seconds} onChange={e => change('timeout_seconds', e.target.valueAsNumber)} /></label>}
        <p className="target-adapter">Adapter: <strong>{form.protocol === 'mcp-jsonrpc' ? 'generic_mcp_jsonrpc' : 'generic_http'}</strong>. {form.protocol === 'mcp-jsonrpc' ? 'The service identifier is internal; tools/list never invokes a tool.' : form.protocol === 'http-json' ? 'Custom HTTP JSON executes through the shared generic_http adapter; inline evidence remains target-reported.' : 'Metadata alone does not verify chat behavior.'}</p>
        {platformNeedsConfirmation && <label className="target-consent"><input type="checkbox" checked={platformConfirmed} onChange={e => setPlatformConfirmed(e.target.checked)} /><span>I confirm this operator-declared platform association. Target ID and connection binding remain unchanged.</span></label>}
        {discoveryId && <div className="quick-connect" aria-label="Discovered target connection">
          <p>Testing endpoint: <code>{form.endpoint}</code> ({form.protocol}).</p>
          {!discoveryBindingValid && <p role="alert">Endpoint or protocol changed. Enter the new URL above and run Discover again before testing or saving.</p>}
          {form.protocol === 'http-json' && <>
            <label>Benign connection-test sample input<input maxLength={512} value={sampleInput} onChange={e => { setSampleInput(e.target.value); setQuickConfirmed(false); }} placeholder={DEFAULT_SAMPLE_INPUT} /></label>
            {resolvedPreviewBody && <details><summary>Preview request payload before sending</summary><pre className="probe-preview-pre">{`POST ${form.endpoint}\nHeaders: ${JSON.stringify(buildRedactedPreviewHeaders(form.http_config?.headers, form.credential_alias, form.session_auth))}\nTimeout: ${form.timeout_seconds}s (no retry)\n${resolvedPreviewBody}`}</pre></details>}
          </>}
          {(!quickProbe || quickProbe.connection_status !== 'succeeded' || quickProbe.runtime_protocol_compatible !== true) && <>
            <label className="target-consent"><input type="checkbox" checked={quickConfirmed} onChange={e => setQuickConfirmed(e.target.checked)} /><span>I authorize one benign connection probe to this exact endpoint.{form.protocol === 'http-json' ? ' POST endpoints may execute target actions; no retries or security payloads are sent.' : ''}</span></label>
            <button className="primary" type="button" disabled={busy || !quickConfirmed || !probeInputReady || !discoveryBindingValid} onClick={probeQuick}>{busy ? 'Checking...' : textPathMissing ? 'Send Sample Probe' : 'Test Connection'}</button>
          </>}
          <p className={`connection-feedback ${quickProbe?.connection_status === 'succeeded' && quickProbe.runtime_protocol_compatible === true ? 'is-connected' : quickProbe || quickError ? 'is-failed' : ''}`} role="status">{busy ? 'Checking' : quickProbe?.connection_status === 'succeeded' && quickProbe.runtime_protocol_compatible === true ? 'Connected' : quickProbe || quickError ? 'Failed' : 'Unverified'}: {quickProbe ? quickProbe.reason.replaceAll('_', ' ') : quickError || quickProbeWaitingMessage}</p>
          {quickProbe && form.protocol === 'http-json' && (
            <ProbeDiagnosticsPanel
              probe={quickProbe}
              currentConfig={form.http_config}
              onApplyTextPath={path => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, text_path: path } }), true)}
              onApplyCorrelationPath={path => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, correlation_id_path: path } }), true)}
              onApplyStatusPath={path => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, status_path: path } }), true)}
              onApplyEvidenceMapping={mapping => updateHttpConfig(prev => ({ ...prev, response: { ...prev.response, evidence_mapping: mapping } }), true)}
            />
          )}
        </div>}
        {quickError && <p role="alert">{quickError}</p>}
        {!discoveryId && <button type="button" disabled={busy || !!bodyJsonError || !!headerError || hasUnresolvedFields || discoveryAuthBlocked || pendingSessionCredential || textPathMissing} onClick={validate}>Validate Target Details</button>}
        {discoveryId && form.protocol === 'http-json' && <button type="button" disabled={busy || !!bodyJsonError || !!headerError || hasUnresolvedFields || discoveryAuthBlocked || pendingSessionCredential || textPathMissing} onClick={validate}>Validate Draft Details</button>}
        <div className="target-form-actions"><button className="primary target-save" type="submit" disabled={busy || !checked || !!bodyJsonError || !!headerError || hasUnresolvedFields || discoveryAuthBlocked || pendingSessionCredential || textPathMissing || !discoveryBindingValid || !!existingEndpoint || !!platformNeedsConfirmation && !platformConfirmed}>{discoveryId ? 'Save Target' : 'Save Configuration'}</button>
          <button type="button" disabled={busy} onClick={() => { generation.current++; releasePendingDraftRefs(); setSessionAuthBusy(false); setMode(null); setDiscovering(false); onDiscoveryFlowChange?.(false); }}>Cancel</button></div>
      </form>}
    </>)}
    {target && !mode && !discovering && !awaitingSelection && <div className="target-summary" aria-label="Selected target">
      <div className="target-summary-heading"><div><h2>{target.name}</h2><p className="caption">{target.protocol === 'openai-chat' ? 'OpenAI-compatible HTTP' : target.protocol === 'http-json' ? 'HTTP JSON (generic_http)' : 'MCP JSON-RPC'}</p></div>
        <span className="target-pill">{target.authorization_status === 'review_required' ? 'Review required' : 'Reviewed'}</span></div>
      <div className="target-endpoint"><span title={target.endpoint}>{new URL(target.endpoint).host}</span><span>Model / Agent: <strong>{target.default_model || 'Not specified'}</strong></span></div>
      {target.protocol === 'http-json' && target.session_auth && enabled && (localSingleUser || unlocked) && (
        <div className="saved-session-auth" role="region" aria-label="Saved target session authentication">
          <div className="auth-control-head">
            <strong>Session Authentication ({target.session_auth.auth_type === 'bearer' ? 'Bearer Token' : `API Key Header: ${target.session_auth.header_name}`})</strong>
            <span className={`auth-availability-pill ${target.credential_availability === 'available' ? 'is-available' : 'is-unavailable'}`}>
              {target.credential_availability === 'available' ? 'Available in Backend memory' : 'Unavailable — supply credential again'}
            </span>
          </div>
          <p className="caption">
            Session credentials live in Backend memory only and must be supplied again after a Backend restart, while this saved Target configuration remains available.
          </p>
          <div className="session-auth-row">
            <label>
              {target.session_auth.auth_type === 'bearer' ? 'Supply or replace Bearer Token' : `Supply or replace ${target.session_auth.header_name}`}
              <input
                type="password"
                autoComplete="off"
                placeholder={target.credential_availability === 'available' ? 'Enter new value to replace' : 'Paste session credential'}
                value={savedSessionInput}
                onChange={e => setSavedSessionInput(e.target.value)}
              />
            </label>
            <button
              type="button"
              disabled={savedSessionBusy || !savedSessionInput.trim()}
              onClick={() => void updateSavedSessionCredential()}
            >
              {savedSessionBusy ? 'Updating...' : target.credential_availability === 'available' ? 'Update Session Credential' : 'Supply Session Credential'}
            </button>
            {target.credential_availability === 'available' && (
              <button
                type="button"
                disabled={savedSessionBusy}
                onClick={() => void clearSavedSessionCredential()}
              >
                Clear Session Credential
              </button>
            )}
          </div>
          {savedSessionMessage && <p role="status" className="caption">{savedSessionMessage}</p>}
        </div>
      )}
      <div className="target-connect">
        <div role="status"><strong className={`target-connection ${connection === 'Connected' ? 'is-connected' : connection === 'Connection failed' ? 'is-failed' : ''}`}>{connection}</strong>
          <p className="caption">{connection === 'Connected' ? 'Target responded successfully.' : connection === 'Checking' ? 'Sending one authorized benign request.' : connection === 'Connection failed' ? (ownProbe?.verification_state === 'response_mapping_unresolved' ? 'Transport succeeded, but response mapping is unresolved.' : 'Unable to confirm a compatible response.') : !settingsMatch ? 'Save changed settings with Edit Target before probing.' : target.connection_verification?.status === 'expired' || target.connection_verification?.status === 'stale' ? 'Previous connection check expired. Test again.' : 'Connection not checked.'}</p></div>
        {enabled && (localSingleUser || unlocked) && <div className="target-connect-actions">
          {target.authorization_status === 'review_required' && (!localSingleUser || !probeAvailable || webLabReview || quickSavedProbe) ? <>
            <label className="target-consent"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} /> I confirm authorization to test {target.endpoint}</label>
            <button disabled={!confirmed || busy} onClick={review}>{localSingleUser ? 'Authorize target for test selection' : 'Review / Approve Target'}</button>
            <p className="caption">Review this exact profile. No request is sent. Security payloads require a separate execution grant.</p>
          </> : null}
          {(connection !== 'Connected' || (quickSavedProbe && target.connection_verification !== undefined && target.connection_verification.status !== 'compatible')) && ((!quickSavedProbe && (!webLabReview || target.authorization_status === 'reviewed_for_offline_configuration' && probeAvailable)) ||
            (quickSavedProbe && target.authorization_status === 'reviewed_for_offline_configuration')) && <>
              {target.protocol === 'http-json' && <>
                <label>Benign connection-test sample input<input maxLength={512} value={sampleInput} disabled={checking || !settingsMatch || configurationInvalid} onChange={e => { setSampleInput(e.target.value); setConfirmed(false); }} placeholder={DEFAULT_SAMPLE_INPUT} /></label>
                {savedHttpPreviewBody && <details><summary>Preview request payload before sending</summary><pre className="probe-preview-pre">{`POST ${target.endpoint}\nHeaders: ${JSON.stringify(buildRedactedPreviewHeaders(target.http_config?.headers, target.credential_alias, target.session_auth))}\nTimeout: ${target.timeout_default}s (no retry)\n${savedHttpPreviewBody}`}</pre></details>}
              </>}
              {probeConfirmationRequired && <label className="target-consent"><input type="checkbox" checked={confirmed} disabled={checking || !settingsMatch || configurationInvalid} onChange={e => setConfirmed(e.target.checked)} /> I confirm authorization for one benign probe to {target.protocol === 'http-json' ? target.endpoint : new URL(target.endpoint).host}</label>}
              <button className="primary" disabled={busy || !nonce || !probeAvailable || !confirmed || !settingsMatch || configurationInvalid} onClick={testConnection}>{checking ? 'Checking...' : connection === 'Connection failed' ? 'Retry' : 'Test Connection'}</button>
            </>}
        </div>}
        {(!enabled || !(localSingleUser || unlocked)) && <button disabled>Test Connection</button>}
      </div>
      {!probeAvailable && <p className="caption">{target.authorization_status === 'review_required' ? 'Review this profile before connecting.' : 'A safe connection probe is not supported for this profile.'}</p>}
      {!enabled && <p className="caption">Target management is unavailable in this service.</p>}
      {(probe || probeFailed) && (probe && target.protocol === 'http-json'
        ? <ProbeDiagnosticsPanel probe={probe} currentConfig={target.http_config} />
        : <details className="target-probe-details"><summary>Connection details</summary><p>{probe ? `Reason: ${probe.reason.replaceAll('_', ' ')}. HTTP status: ${probe.http_status ?? 'unavailable'}. API compatibility: ${probe.runtime_protocol_compatible === null ? 'unknown' : probe.runtime_protocol_compatible ? 'yes' : 'no'}. Requests: ${probe.target_request_count}.` : 'No connection proof was obtained.'}</p></details>)}
    </div>}
    {message && <p role="status">{message}</p>}{error && <p role="alert">{error}</p>}
    {target && !discovering && !awaitingSelection && enabled && (localSingleUser || unlocked) && <details className="target-advanced target-context-drawer"><summary>Application Context · Optional</summary><ApplicationContext key={identity + nonce} target={target} nonce={nonce} secret={secret} discovery={discoveryResult} /></details>}
    {target && evidenceEnabled && !discovering && !awaitingSelection && <details className="target-advanced target-evidence-drawer"><summary>Evidence Sources · Optional</summary><EvidenceSources key={identity + nonce} target={target} nonce={nonce} secret={secret} authorized={enabled && (localSingleUser || unlocked)} /></details>}
  </div>;
}
