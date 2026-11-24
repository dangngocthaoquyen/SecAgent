import { describe, expect, it } from 'vitest';
import {
  inspectEvidenceItemVerification,
  summarizeCaseEvidenceVerification,
  summarizeRunEvidenceVerification,
} from './scanFormatters';
import type { GenericEvidenceItem, GenericRunCaseResult } from './testingApi';

function makeCase(id: string, evidence: GenericEvidenceItem[]): GenericRunCaseResult {
  return {
    case_id: id,
    status: 'INCONCLUSIVE',
    verdict: 'INCONCLUSIVE',
    evidence,
  } as unknown as GenericRunCaseResult;
}

describe('Task 1.1B Evidence Verification Integrity (Frontend)', () => {
  it('rejects execution_verified=true when provenance is missing (null)', () => {
    const info = inspectEvidenceItemVerification({
      kind: 'tool_call',
      source: 'runtime_trace',
      data: { execution_verified: true },
    });
    expect(info.isExecutionVerified).toBe(false);
    expect(info.verificationLabel).toBe('Execution not verified');
  });

  it('rejects unknown or untrusted sources even with independent provenance and execution_verified=true', () => {
    const unknownSource = inspectEvidenceItemVerification({
      kind: 'tool_call',
      source: 'unknown_untrusted_plugin',
      data: {
        provenance: 'independent_observer',
        execution_verified: true,
        scope: 'agent_run',
      },
    });
    expect(unknownSource.isExecutionVerified).toBe(false);
    expect(unknownSource.verificationLabel).toBe('Execution not verified');

    const httpSource = inspectEvidenceItemVerification({
      kind: 'declared_tool_call',
      source: 'http_response',
      data: {
        provenance: 'independent_observer',
        execution_verified: true,
      },
    });
    expect(httpSource.isExecutionVerified).toBe(false);
    expect(httpSource.verificationLabel).toBe('Execution not verified');
  });

  it('rejects independent provenance when execution_verified is false or missing', () => {
    const unverifiedCollector = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'sandbox_log_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: false,
        correlation_status: 'matched',
        correlation_strength: 'strong',
        verification_status: 'sandbox_log_unverified',
      },
    });
    expect(unverifiedCollector.isExecutionVerified).toBe(false);
    expect(unverifiedCollector.verificationLabel).toBe('Execution not verified');

    const missingVerified = inspectEvidenceItemVerification({
      kind: 'tool_call',
      source: 'runtime_trace',
      data: {
        provenance: 'independent_observer',
      },
    });
    expect(missingVerified.isExecutionVerified).toBe(false);
    expect(missingVerified.verificationLabel).toBe('Verification not recorded');
  });

  it('rejects weak, uncorrelated, or contradictory correlation and verification metadata', () => {
    const weakCorr = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'sandbox_log_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: true,
        correlation_status: 'matched',
        correlation_strength: 'weak',
      },
    });
    expect(weakCorr.isExecutionVerified).toBe(false);
    expect(weakCorr.verificationLabel).toBe('Execution not verified');

    const uncorrelated = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'http_callback_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: true,
        correlation_status: 'uncorrelated',
        correlation_strength: 'none',
      },
    });
    expect(uncorrelated.isExecutionVerified).toBe(false);
    expect(uncorrelated.verificationLabel).toBe('Execution not verified');

    const conflictingStatus = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'sandbox_log_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: true,
        correlation_status: 'matched',
        correlation_strength: 'strong',
        verification_status: 'conflicting_execution_metadata',
      },
    });
    expect(conflictingStatus.isExecutionVerified).toBe(false);
    expect(conflictingStatus.verificationLabel).toBe('Execution not verified');

    const explicitExecutedFalse = inspectEvidenceItemVerification({
      kind: 'tool_call',
      source: 'runtime_trace',
      data: {
        provenance: 'independent_observer',
        execution_verified: true,
        executed: false,
      },
    });
    expect(explicitExecutedFalse.isExecutionVerified).toBe(false);
    expect(explicitExecutedFalse.verificationLabel).toBe('Execution not verified');

    const effectObservedFalse = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'file_artifact_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: true,
        effect_observed: false,
        correlation_status: 'matched',
        correlation_strength: 'strong',
      },
    });
    expect(effectObservedFalse.isExecutionVerified).toBe(false);
    expect(effectObservedFalse.verificationLabel).toBe('Execution not verified');
  });

  it('enforces Backend-Frontend parity: collected_evidence with missing/null correlation_status or correlation_strength is NOT verified', () => {
    const missingStrength = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'sandbox_log_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: true,
        correlation_status: 'matched',
        verification_status: 'verified',
      },
    });
    expect(missingStrength.isExecutionVerified).toBe(false);
    expect(missingStrength.verificationLabel).toBe('Execution not verified');

    const missingStatus = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'file_artifact_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: true,
        correlation_strength: 'strong',
        verification_status: 'verified',
      },
    });
    expect(missingStatus.isExecutionVerified).toBe(false);
    expect(missingStatus.verificationLabel).toBe('Execution not verified');

    const bothMissing = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'http_callback_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: true,
      },
    });
    expect(bothMissing.isExecutionVerified).toBe(false);
    expect(bothMissing.verificationLabel).toBe('Execution not verified');
  });

  it('distinguishes valid WebFixture receipt from zero-receipt control run', () => {
    const zeroReceipt = inspectEvidenceItemVerification({
      kind: 'collector_receipt',
      source: 'local_collector',
      data: {
        provenance: 'independent_local_collector',
        execution_verified: false,
        correlation_valid: false,
        page_served: true,
        receipt_count: 0,
      },
    });
    expect(zeroReceipt.isExecutionVerified).toBe(false);
    expect(zeroReceipt.verificationLabel).toBe('Execution not verified');

    const validReceipt = inspectEvidenceItemVerification({
      kind: 'collector_receipt',
      source: 'local_collector',
      data: {
        provenance: 'independent_local_collector',
        execution_verified: true,
        correlation_valid: true,
        page_served: true,
        receipt_count: 1,
      },
    });
    expect(validReceipt.isExecutionVerified).toBe(true);
    expect(validReceipt.verificationLabel).toBe('Execution verified');
  });

  it('accepts valid strongly-correlated collector and trusted observer items including executed+failed outcome', () => {
    const strongCollector = inspectEvidenceItemVerification({
      kind: 'collected_evidence',
      source: 'sandbox_log_collector',
      data: {
        provenance: 'independently_verified',
        execution_verified: true,
        correlation_status: 'matched',
        correlation_strength: 'strong',
        verification_status: 'verified',
      },
    });
    expect(strongCollector.isExecutionVerified).toBe(true);
    expect(strongCollector.verificationLabel).toBe('Execution verified');

    const trustedToolCall = inspectEvidenceItemVerification({
      kind: 'tool_call',
      source: 'runtime_trace',
      data: {
        provenance: 'independent_observer',
        execution_verified: true,
        scope: 'agent_run',
      },
    });
    expect(trustedToolCall.isExecutionVerified).toBe(true);
    expect(trustedToolCall.verificationLabel).toBe('Execution verified');

    const runSummary = summarizeRunEvidenceVerification([
      makeCase('C1', [strongCollector.ev]),
      makeCase('C2', [
        {
          kind: 'collected_evidence',
          source: 'sandbox_log_collector',
          data: {
            provenance: 'adapter_observed',
            execution_verified: false,
            correlation_status: 'matched',
            correlation_strength: 'strong',
            verification_status: 'sandbox_log_unverified',
          },
        },
      ]),
    ]);
    expect(runSummary.totalCases).toBe(2);
    expect(runSummary.verifiedCaseCount).toBe(1);
    expect(runSummary.verifiedItemCount).toBe(1);
    expect(runSummary.unverifiedItemCount).toBe(1);
    expect(summarizeCaseEvidenceVerification(makeCase('C3', [])).hasVerifiedExecution).toBe(false);
  });

  it('Stage A1 parity: rejects all 4 cross-contract kind/source/provenance and casing mismatches', () => {
    // 1. tool_call with collector source
    expect(
      inspectEvidenceItemVerification({
        kind: 'tool_call',
        source: 'sandbox_log_collector',
        data: { provenance: 'independent_observer', execution_verified: true },
      }).isExecutionVerified,
    ).toBe(false);

    // 2. tool_call with independent_local_collector provenance
    expect(
      inspectEvidenceItemVerification({
        kind: 'tool_call',
        source: 'runtime_trace',
        data: { provenance: 'independent_local_collector', execution_verified: true },
      }).isExecutionVerified,
    ).toBe(false);

    // 3. collector_receipt with independent_observer provenance
    expect(
      inspectEvidenceItemVerification({
        kind: 'collector_receipt',
        source: 'local_collector',
        data: {
          provenance: 'independent_observer',
          execution_verified: true,
          correlation_valid: true,
          page_served: true,
        },
      }).isExecutionVerified,
    ).toBe(false);

    // 4. collected_evidence with uppercase MATCHED / STRONG
    expect(
      inspectEvidenceItemVerification({
        kind: 'collected_evidence',
        source: 'sandbox_log_collector',
        data: {
          provenance: 'independently_verified',
          execution_verified: true,
          correlation_status: 'MATCHED',
          correlation_strength: 'STRONG',
        },
      }).isExecutionVerified,
    ).toBe(false);
  });

  it('Stage A2/A4 parity: handles malformed metadata safely and applies contract-specific effect_observed semantics', () => {
    // Malformed list/dict fields fail closed without throwing
    expect(
      inspectEvidenceItemVerification({
        kind: 'tool_call',
        source: 'runtime_trace',
        data: { provenance: ['independent_observer'], execution_verified: true },
      }).isExecutionVerified,
    ).toBe(false);

    expect(
      inspectEvidenceItemVerification({
        kind: 'tool_call',
        source: 'runtime_trace',
        data: { provenance: 'independent_observer', execution_verified: true, execution_semantics: [] },
      }).isExecutionVerified,
    ).toBe(false);

    // Command log with executed=true and effect_observed=false can still be verified execution
    expect(
      inspectEvidenceItemVerification({
        kind: 'collected_evidence',
        source: 'sandbox_log_collector',
        data: {
          provenance: 'independently_verified',
          execution_verified: true,
          effect_observed: false,
          correlation_status: 'matched',
          correlation_strength: 'strong',
        },
      }).isExecutionVerified,
    ).toBe(true);

    // simulated_handler_invocation is never verified execution
    expect(
      inspectEvidenceItemVerification({
        kind: 'collected_evidence',
        source: 'sandbox_log_collector',
        data: {
          provenance: 'independently_verified',
          execution_verified: true,
          execution_semantics: 'simulated_handler_invocation',
          correlation_status: 'matched',
          correlation_strength: 'strong',
        },
      }).isExecutionVerified,
    ).toBe(false);
  });

  it('Task 1.2B: normalized XML model_reported_tool_intent is never displayed as verified execution', () => {
    const xmlIntent = inspectEvidenceItemVerification({
      kind: 'model_reported_tool_intent',
      source: 'response_output_tool_intent',
      name: 'xml_tool_invocation_markup',
      data: {
        provenance: 'model_reported',
        execution_verified: false,
        observation_scope: 'model_response_text',
        execution_semantics: 'model_text_intent',
        verification_status: 'model_reported_unverified',
        format: 'xml_tool_call',
        invoked_tool_names: ['ledger.transfer'],
      },
    });
    expect(xmlIntent.isExecutionVerified).toBe(false);
    expect(xmlIntent.verificationLabel).toBe('Execution not verified');

    // Even if conflicting execution_verified=true were injected on response_output_tool_intent
    const spoofedIntent = inspectEvidenceItemVerification({
      kind: 'model_reported_tool_intent',
      source: 'response_output_tool_intent',
      data: {
        provenance: 'independent_observer',
        execution_verified: true,
      },
    });
    expect(spoofedIntent.isExecutionVerified).toBe(false);
    expect(spoofedIntent.verificationLabel).toBe('Execution not verified');
  });

  it('G01 Fix 2 whitespace parity: rejects padded provenance, correlation_status, and execution_semantics', () => {
    // 1. Padded provenance -> rejected (matches Backend=False)
    expect(
      inspectEvidenceItemVerification({
        kind: 'tool_call',
        source: 'runtime_trace',
        data: {
          provenance: ' independent_observer ',
          execution_verified: true,
        },
      }).isExecutionVerified,
    ).toBe(false);

    // 2. Padded correlation_status -> rejected (matches Backend=False)
    expect(
      inspectEvidenceItemVerification({
        kind: 'collected_evidence',
        source: 'sandbox_log_collector',
        data: {
          provenance: 'independently_verified',
          correlation_status: 'matched ',
          correlation_strength: 'strong',
          execution_verified: true,
        },
      }).isExecutionVerified,
    ).toBe(false);

    // 3. Padded non-execution semantics -> rejected (matches Backend=False)
    expect(
      inspectEvidenceItemVerification({
        kind: 'tool_call',
        source: 'runtime_trace',
        data: {
          provenance: 'independent_observer',
          execution_verified: true,
          execution_semantics: ' simulated_handler_invocation ',
        },
      }).isExecutionVerified,
    ).toBe(false);
  });
});
