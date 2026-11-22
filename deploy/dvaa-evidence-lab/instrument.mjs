// Build-only patch for a separate, pinned DVAA lab image. No original container is edited.
import fs from 'fs';
import crypto from 'crypto';

const file = process.argv[2];
const original = fs.readFileSync(file, 'utf8');
const digest = crypto.createHash('sha256').update(original).digest('hex');
if (digest !== '0f62cbb0c134ba41b944726a7eff22cfb53db74cfb6116ce2e6847379fac91a8') {
  throw new Error('Unreviewed DVAA source revision; refusing instrumentation.');
}
let source = original.replace(/\r\n/g, '\n');
function replaceOnce(before, after) {
  if (source.split(before).length !== 2) throw new Error('DVAA handler anchor mismatch.');
  source = source.replace(before, after);
}
replaceOnce("import http from 'http';", "import http from 'http';\nimport crypto from 'crypto';");
replaceOnce('const result = await executeMcpTool(agent, toolName, toolArgs);',
            'const result = await executeMcpTool(agent, toolName, toolArgs, rpcId);');

const receiptCode = `
// SecAgent instrumented lab only: handler-owned, target-origin telemetry.
// This does not attest host execution, a complete agent trace, or Agent selection.
function labReceipt(agent, name, args, requestId) {
  const root = process.env.SECAGENT_LAB_EVIDENCE_DIR;
  if (agent.id !== 'toolbot' || !root || !/^[a-f0-9]{32}$/.test(requestId)) return null;
  const canonical = value => Array.isArray(value)
    ? '[' + value.map(canonical).join(',') + ']'
    : value && typeof value === 'object'
      ? '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
      : JSON.stringify(value);
  const argumentsSha256 = crypto.createHash('sha256').update(canonical(args)).digest('hex');
  const receipt = {
    schema_version: '1.0', target_id: 'dvaa-toolbot', request_id: requestId,
    execution_id: requestId, invocation_id: crypto.randomBytes(16).toString('hex'),
    tool_name: name, arguments_sha256: argumentsSha256,
    attribution: 'direct_request', provenance: 'instrumented_target_handler',
    source_provenance: 'instrumented_dvaa_lab', trace_completeness: 'partial',
    handler_entry: true, handler_status: 'entered',
    entered_at: new Date().toISOString()
  };
  fs.mkdirSync(root, { recursive: true });
  const destination = path.join(root, requestId + '.receipt.json');
  if (fs.existsSync(destination)) throw new Error('Duplicate lab request identity.');
  const write = () => {
    const temporary = path.join(root, '.' + requestId + '.' + receipt.invocation_id + '.tmp');
    fs.writeFileSync(temporary, JSON.stringify(receipt), { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporary, destination);
  };
  write();
  return { receipt, write };
}
function finishLabReceipt(record, result, status) {
  if (!record) return;
  record.receipt.handler_status = status;
  record.receipt.handler_result = true;
  record.receipt.result_sha256 = crypto.createHash('sha256').update(JSON.stringify(result)).digest('hex');
  record.receipt.finished_at = new Date().toISOString();
  record.write();
}
`;
replaceOnce('async function executeMcpTool(agent, toolName, args) {',
            receiptCode + '\nasync function executeMcpTool(agent, toolName, args, requestId = null) {\n  const labRecord = labReceipt(agent, toolName, args, requestId);');
replaceOnce('  if (!tool) {\n    return { error: `Tool ${toolName} not found` };\n  }',
            '  if (!tool) {\n    const absent = { error: `Tool ${toolName} not found` };\n    finishLabReceipt(labRecord, absent, "rejected");\n    return absent;\n  }');
replaceOnce('    if (result) return result;',
            '    if (result) {\n      finishLabReceipt(labRecord, result, result.success === true ? "succeeded" : "failed");\n      return result;\n    }');
replaceOnce("  return { success: true, result: 'Tool executed (secure mode)' };",
            "  const secure = { success: true, result: 'Tool executed (secure mode)' };\n  finishLabReceipt(labRecord, secure, 'succeeded');\n  return secure;");
fs.writeFileSync(file, source);
console.log('Pinned DVAA lab handler instrumentation applied.');
