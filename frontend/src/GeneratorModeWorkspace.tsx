import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  getEphemeralOperatorSecret,
  testingApi,
  type DatasetSummary,
  type TargetPreset,
} from './testingApi';
import GenerateAndRunPrepPanel from './GenerateAndRunPrepPanel';
import GeneratorOnlyPanel from './GeneratorOnlyPanel';
import {
  GeneratorApiError,
  SUPPORTED_ASI_CODES,
  createDefaultGeneratorConfig,
  extractActiveCounts,
  generatorApi,
  type GeneratorConfigState,
  type GeneratorJudgeStatus,
  type GeneratorOperatingMode,
  type GeneratorProviderStatus,
  type PreviewSaveRecord,
  type TargetReadinessReport,
} from './generatorApi';

function buildReadinessFingerprint(cfg: GeneratorConfigState): string {
  const activeAsi: string[] = [];
  const scopes: Record<string, string> = {};
  const policies: Record<string, string> = {};
  for (const code of SUPPORTED_ASI_CODES) {
    if (!cfg.selectedAsi[code]) continue;
    activeAsi.push(code);
    if (cfg.requestedScopes[code]) scopes[code] = cfg.requestedScopes[code]!;
    if (cfg.policyIdsByAsi[code]) policies[code] = cfg.policyIdsByAsi[code]!;
  }
  return JSON.stringify({
    targetId: cfg.targetId,
    activeAsi,
    scopes,
    policies,
  });
}

export type GeneratorModeWorkspaceProps = {
  targets?: TargetPreset[];
  nonce?: string;
  secret?: string;
  initialMode?: GeneratorOperatingMode;
  initialTargetId?: string;
  existingDatasets?: DatasetSummary[];
  onSelectTarget?: (targetId: string) => void;
  onDatasetSaved?: (record: PreviewSaveRecord) => void;
  onOpenDatasetLibrary?: (datasetId?: string) => void;
  onOpenExistingScan?: (datasetId?: string) => void;
  onOpenRunReport?: (runId: string) => void;
};

const MODE_DESCRIPTIONS: Record<
  GeneratorOperatingMode,
  { title: string; badge: string; summary: string }
> = {
  generate_and_run: {
    title: 'Generate & Run',
    badge: 'Primary Workflow · G11.6',
    summary:
      'Configure → Generate → Validate → Auto-Save Dataset → Preflight → Execute → Evaluate → Report (no mandatory preview/manual save step).',
  },
  generate_only: {
    title: 'Generate Only',
    badge: 'Active · G11.3C',
    summary:
      'Configure → Generate → Preview → Edit/Select → Explicit Save into Dataset Library (never executes Target or Judge).',
  },
  run_existing_dataset: {
    title: 'Run Existing Dataset',
    badge: 'Existing Scan Flow',
    summary:
      'Select an imported or previously generated dataset and run SecAgent evaluation without calling Generator.',
  },
};

/**
 * Unified three-mode Generator & Scan entry workspace for SecAgent (G11.4 + G11.6).
 *
 * Works both integrated inside App.tsx (auto-bootstrapping health/targets/datasets via testingApi)
 * and with injected props in unit tests.
 */
export default function GeneratorModeWorkspace({
  targets: propTargets,
  nonce: propNonce,
  secret: propSecret,
  initialMode = 'generate_and_run',
  initialTargetId = '',
  existingDatasets: propExistingDatasets,
  onSelectTarget,
  onDatasetSaved,
  onOpenDatasetLibrary,
  onOpenExistingScan,
  onOpenRunReport,
}: GeneratorModeWorkspaceProps = {}) {
  const [loadedTargets, setLoadedTargets] = useState<TargetPreset[]>([]);
  const [loadedNonce, setLoadedNonce] = useState('');
  const [loadedDatasets, setLoadedDatasets] = useState<DatasetSummary[]>([]);
  const [bootstrapError, setBootstrapError] = useState('');

  const targets = propTargets ?? loadedTargets;
  const nonce = propNonce ?? loadedNonce;
  const secret = propSecret ?? getEphemeralOperatorSecret();
  const existingDatasets = propExistingDatasets ?? loadedDatasets;

  const [mode, setMode] = useState<GeneratorOperatingMode>(initialMode);
  const [config, setConfig] = useState<GeneratorConfigState>(() =>
    createDefaultGeneratorConfig(initialTargetId || targets[0]?.id || ''),
  );
  const [providerStatus, setProviderStatus] = useState<GeneratorProviderStatus | null>(null);
  const [judgeStatus, setJudgeStatus] = useState<GeneratorJudgeStatus | null>(null);
  const [generateAndRunAvailable, setGenerateAndRunAvailable] = useState(false);
  const [providerStatusError, setProviderStatusError] = useState('');
  const [readiness, setReadiness] = useState<TargetReadinessReport | null>(null);
  const [readinessLoading, setReadinessLoading] = useState(false);
  const [readinessError, setReadinessError] = useState('');

  const readinessSeqRef = useRef(0);
  const readinessAbortRef = useRef<AbortController | null>(null);
  const readinessKey = useMemo(() => buildReadinessFingerprint(config), [config]);

  // Self-bootstrap workflow API context when mounted inside App.tsx without injected props.
  useEffect(() => {
    if (propTargets !== undefined && propNonce !== undefined) return;
    const controller = new AbortController();
    setBootstrapError('');
    Promise.all([
      testingApi.health(controller.signal),
      testingApi.targets(controller.signal),
    ])
      .then(([healthRes, targetsRes]) => {
        if (controller.signal.aborted) return;
        setLoadedNonce(healthRes.nonce);
        setLoadedTargets(targetsRes.targets);
        if (propExistingDatasets === undefined) {
          testingApi
            .listDatasets(secret, healthRes.nonce)
            .then((ds) => {
              if (!controller.signal.aborted) setLoadedDatasets(ds);
            })
            .catch(() => {
              // Dataset list may require operator auth in non-local mode.
            });
        }
      })
      .catch((err) => {
        if (controller.signal.aborted) return;
        setBootstrapError(
          err instanceof Error ? err.message : 'Unable to connect to Workflow API.',
        );
      });
    return () => controller.abort();
  }, [propTargets, propNonce, propExistingDatasets, secret]);

  const handleConfigChange = useCallback(
    (next: GeneratorConfigState) => {
      setConfig(next);
      if (next.targetId && next.targetId !== config.targetId) {
        onSelectTarget?.(next.targetId);
      }
    },
    [config.targetId, onSelectTarget],
  );

  const refreshDatasetsIfManaged = useCallback(() => {
    if (propExistingDatasets !== undefined || !nonce) return;
    testingApi
      .listDatasets(secret, nonce)
      .then((ds) => setLoadedDatasets(ds))
      .catch(() => {});
  }, [propExistingDatasets, nonce, secret]);

  // Keep targetId aligned when targets list populates asynchronously.
  useEffect(() => {
    if (!config.targetId && targets.length > 0) {
      const nextId = initialTargetId && targets.some((t) => t.id === initialTargetId)
        ? initialTargetId
        : targets[0].id;
      setConfig((prev) => ({ ...prev, targetId: nextId }));
    }
  }, [config.targetId, targets, initialTargetId]);

  // R02: Immediately invalidate stale readiness and abort in-flight requests whenever
  // target, selected ASIs, requested scopes, or reviewed policy bindings change.
  useEffect(() => {
    readinessAbortRef.current?.abort();
    readinessAbortRef.current = null;
    readinessSeqRef.current += 1;
    setReadiness(null);
    setReadinessError('');
    setReadinessLoading(false);
    return () => {
      readinessAbortRef.current?.abort();
    };
  }, [readinessKey]);

  // Only query Generator status when a Generator mode is active (Mode 3 NEVER calls Generator).
  useEffect(() => {
    if (mode === 'run_existing_dataset' || !nonce) return;
    const controller = new AbortController();
    setProviderStatusError('');
    generatorApi
      .getStatus(nonce, secret, controller.signal)
      .then((res) => {
        if (!controller.signal.aborted) {
          setProviderStatus(res.provider);
          setJudgeStatus(res.judge ?? null);
          setGenerateAndRunAvailable(res.generate_and_run_available === true);
        }
      })
      .catch((err) => {
        if (controller.signal.aborted) return;
        setGenerateAndRunAvailable(false);
        setJudgeStatus(null);
        setProviderStatusError(
          err instanceof GeneratorApiError
            ? `${err.code}: ${err.message}`
            : err instanceof Error
              ? err.message
              : 'Generator status unavailable.',
        );
      });
    return () => controller.abort();
  }, [mode, nonce, secret]);

  const handleCheckReadiness = useCallback(() => {
    if (!config.targetId || !nonce) return;
    readinessAbortRef.current?.abort();
    const controller = new AbortController();
    readinessAbortRef.current = controller;
    const seq = ++readinessSeqRef.current;
    const requestedTargetId = config.targetId;
    const { selectedList } = extractActiveCounts(config);
    setReadinessLoading(true);
    setReadinessError('');

    generatorApi
      .checkReadiness(
        {
          target_id: requestedTargetId,
          selected_asi: selectedList.length > 0 ? selectedList : undefined,
          requested_scopes:
            Object.keys(config.requestedScopes).length > 0 ? config.requestedScopes : undefined,
          policy_ids_by_asi:
            Object.keys(config.policyIdsByAsi).length > 0 ? config.policyIdsByAsi : undefined,
        },
        nonce,
        secret,
        controller.signal,
      )
      .then((report) => {
        if (controller.signal.aborted || readinessSeqRef.current !== seq) return;
        if (report.target_id !== requestedTargetId) return;
        setReadiness(report);
      })
      .catch((err) => {
        if (controller.signal.aborted || readinessSeqRef.current !== seq) return;
        setReadiness(null);
        setReadinessError(
          err instanceof GeneratorApiError
            ? `${err.code}: ${err.message}`
            : err instanceof Error
              ? err.message
              : 'Failed to check context readiness.',
        );
      })
      .finally(() => {
        if (readinessSeqRef.current === seq) {
          setReadinessLoading(false);
        }
      });
  }, [config, nonce, secret]);

  return (
    <div data-testid="generator-mode-workspace">
      <header style={{ marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>AI Security Testcase Generation &amp; Scan Modes</h2>
        <p style={{ margin: '4px 0 0', color: 'var(--muted)' }}>
          Context-aware generation grounded in confirmed Application Context, OWASP Agentic Skills (ASI01/ASI02/ASI03/ASI05), and optional Reviewed Policies.
        </p>
      </header>

      {bootstrapError && (
        <div
          role="alert"
          style={{
            marginBottom: 14,
            padding: 10,
            borderRadius: 8,
            border: '1px solid var(--fail)',
            color: 'var(--fail)',
          }}
        >
          {bootstrapError}
        </div>
      )}

      {/* Three Operating Modes Selector */}
      <div
        role="tablist"
        aria-label="Generator operating modes"
        data-testid="operating-mode-selector"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 10,
          marginBottom: 16,
        }}
      >
        {(
          ['generate_and_run', 'generate_only', 'run_existing_dataset'] as GeneratorOperatingMode[]
        ).map((m) => {
          const meta = MODE_DESCRIPTIONS[m];
          const active = mode === m;
          return (
            <button
              key={m}
              type="button"
              role="tab"
              aria-selected={active}
              data-testid={`mode-tab-${m}`}
              onClick={() => setMode(m)}
              style={{
                textAlign: 'left',
                whiteSpace: 'normal',
                padding: 12,
                borderRadius: 10,
                border: active ? '2px solid var(--teal)' : '1px solid var(--line)',
                background: active ? 'var(--teal-soft)' : 'var(--surface)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6 }}>
                <strong>{meta.title}</strong>
                <span style={{ fontSize: 11, color: 'var(--teal)', fontWeight: 700 }}>{meta.badge}</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 6, fontWeight: 400 }}>
                {meta.summary}
              </div>
            </button>
          );
        })}
      </div>

      {/* Mode 1 — Generate & Run (Primary Workflow — Active in G11.6) */}
      {mode === 'generate_and_run' && (
        <GenerateAndRunPrepPanel
          targets={targets}
          config={config}
          onChangeConfig={handleConfigChange}
          nonce={nonce}
          secret={secret}
          generateAndRunAvailable={generateAndRunAvailable}
          providerStatus={providerStatus}
          judgeStatus={judgeStatus}
          providerStatusError={providerStatusError}
          readiness={readiness}
          readinessLoading={readinessLoading}
          readinessError={readinessError}
          onCheckReadiness={handleCheckReadiness}
          onSwitchToGenerateOnly={() => setMode('generate_only')}
          onSwitchToRunExisting={() => setMode('run_existing_dataset')}
          onOpenDatasetLibrary={onOpenDatasetLibrary}
          onOpenRunReport={onOpenRunReport}
          onDatasetPersisted={refreshDatasetsIfManaged}
        />
      )}

      {/* Mode 2 — Generate Only (Active via G11.3C API) */}
      {mode === 'generate_only' && (
        <GeneratorOnlyPanel
          targets={targets}
          config={config}
          onChangeConfig={handleConfigChange}
          nonce={nonce}
          secret={secret}
          providerStatus={providerStatus}
          providerStatusError={providerStatusError}
          readiness={readiness}
          readinessLoading={readinessLoading}
          readinessError={readinessError}
          onCheckReadiness={handleCheckReadiness}
          onDatasetSaved={(rec) => {
            refreshDatasetsIfManaged();
            onDatasetSaved?.(rec);
          }}
          onOpenDatasetLibrary={(datasetId) => onOpenDatasetLibrary?.(datasetId)}
        />
      )}

      {/* Mode 3 — Run Existing Dataset (Links to existing SecAgent Scan & Dataset Library; zero Generator calls) */}
      {mode === 'run_existing_dataset' && (
        <section
          aria-label="Run Existing Dataset workflow"
          data-testid="run-existing-dataset-panel"
          className="panel"
          style={{ padding: 16 }}
        >
          <h3 style={{ marginTop: 0 }}>Run Existing Dataset (No AI Generation)</h3>
          <p style={{ color: 'var(--muted)' }}>
            Execute any previously imported Promptfoo/custom dataset or saved AI-generated dataset through SecAgent&apos;s existing New Scan &amp; Generic Runner workflow. This mode never calls the Generation LLM Provider.
          </p>

          {existingDatasets.length > 0 ? (
            <div style={{ display: 'grid', gap: 8, marginTop: 12, marginBottom: 14 }}>
              {existingDatasets.map((ds) => (
                <div
                  key={ds.dataset_id}
                  data-testid={`existing-dataset-row-${ds.dataset_id}`}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: 12,
                    padding: 10,
                    border: '1px solid var(--line)',
                    borderRadius: 8,
                  }}
                >
                  <div>
                    <strong>{ds.name}</strong>{' '}
                    <span style={{ fontSize: 12, color: 'var(--muted)' }}>
                      ({ds.total_testcases} testcases · source: <code>{ds.source_tool}</code>)
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <a
                      href="#scan"
                      onClick={(e) => {
                        if (onOpenExistingScan) {
                          e.preventDefault();
                          onOpenExistingScan(ds.dataset_id);
                        }
                      }}
                      style={{ fontWeight: 600, color: 'var(--teal)', textDecoration: 'underline' }}
                    >
                      Run in New Scan
                    </a>
                    <a
                      href="#datasets"
                      onClick={(e) => {
                        if (onOpenDatasetLibrary) {
                          e.preventDefault();
                          onOpenDatasetLibrary(ds.dataset_id);
                        }
                      }}
                      style={{ fontWeight: 600, color: 'var(--ink)', textDecoration: 'underline' }}
                    >
                      Inspect in Library
                    </a>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ fontSize: 13, color: 'var(--muted)' }}>
              Open Dataset Library to browse or import datasets, or go directly to New Scan to select a saved dataset and configure execution.
            </p>
          )}

          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <a
              href="#scan"
              data-testid="existing-open-scan-link"
              onClick={(e) => {
                if (onOpenExistingScan) {
                  e.preventDefault();
                  onOpenExistingScan(undefined);
                }
              }}
              style={{
                padding: '9px 14px',
                borderRadius: 7,
                background: 'var(--teal)',
                color: '#fff',
                fontWeight: 600,
              }}
            >
              Open New Scan
            </a>
            <a
              href="#datasets"
              data-testid="existing-open-library-link"
              onClick={(e) => {
                if (onOpenDatasetLibrary) {
                  e.preventDefault();
                  onOpenDatasetLibrary(undefined);
                }
              }}
              style={{
                padding: '9px 14px',
                borderRadius: 7,
                border: '1px solid var(--line)',
                fontWeight: 600,
              }}
            >
              Open Dataset Library
            </a>
          </div>
        </section>
      )}
    </div>
  );
}
