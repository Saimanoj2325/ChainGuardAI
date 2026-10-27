/**
 * MOCK DATA. Everything in this folder is synthetic and exists only for
 * (a) VITE_USE_MOCKS=true demo mode and (b) automated tests.
 * Every mock finding has is_mock: true and every mock report has contains_mock_data: true.
 */
import type { AuditReport, ContractInfo, Finding, Health, Job, StageEvent, VerifyResponse } from '../api/types';

export const MOCK_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract MockBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() { owner = msg.sender; }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    function kill() external {
        require(tx.origin == owner, "not owner");
        selfdestruct(payable(owner));
    }
}
`;

export const MOCK_CONTRACT: ContractInfo = {
  filename: 'MockBank.sol',
  sha256: '0000000000000000000000000000000000000000000000000000000000000000',
  size_bytes: MOCK_SOURCE.length,
  solc_version: '0.8.19',
  contracts: ['MockBank'],
};

export const MOCK_FINDINGS: Finding[] = [
  {
    id: 'mock-f1',
    vuln_class: 'reentrancy',
    title: '[MOCK] External call before state update in withdraw()',
    severity: 'high',
    confidence: 0.91,
    detectors: ['mock'],
    contract_name: 'MockBank',
    function_name: 'withdraw',
    description: 'MOCK: balances[msg.sender] is zeroed after the external call, allowing re-entry.',
    recommendation: 'Apply checks-effects-interactions or a reentrancy guard.',
    evidence: {
      lines: [{ start: 16, end: 18 }],
      snippet: '(bool ok, ) = msg.sender.call{value: amount}("");\nrequire(ok, "transfer failed");\nbalances[msg.sender] = 0;',
      graph_nodes: ['MockBank.withdraw:CALL', 'MockBank.withdraw:SSTORE balances'],
      dependency_path: ['withdraw()', 'msg.sender.call{value}', 'fallback re-enters withdraw()', 'balances[msg.sender] = 0'],
      tool_output: 'MOCK tool output — not produced by any analyzer.',
    },
    verification: {
      llm_status: 'supported',
      llm_explanation: 'MOCK explanation — no LLM was called.',
      evm_status: 'confirmed',
      evm_details: 'MOCK details — no EVM was run.',
    },
    is_mock: true,
  },
  {
    id: 'mock-f2',
    vuln_class: 'tx_origin',
    title: '[MOCK] tx.origin used for authorization',
    severity: 'medium',
    confidence: 0.78,
    detectors: ['mock'],
    contract_name: 'MockBank',
    function_name: 'kill',
    description: 'MOCK: tx.origin authorization can be bypassed via phishing contracts.',
    recommendation: 'Use msg.sender for authorization.',
    evidence: { lines: [{ start: 22, end: 22 }], snippet: 'require(tx.origin == owner, "not owner");', graph_nodes: [], dependency_path: [], tool_output: null },
    verification: { llm_status: 'uncertain', llm_explanation: 'MOCK.', evm_status: 'not_applicable', evm_details: null },
    is_mock: true,
  },
  {
    id: 'mock-f3',
    vuln_class: 'unprotected_selfdestruct',
    title: '[MOCK] selfdestruct reachable',
    severity: 'low',
    confidence: 0.42,
    detectors: ['mock'],
    contract_name: 'MockBank',
    function_name: 'kill',
    description: 'MOCK: selfdestruct present.',
    recommendation: null,
    evidence: { lines: [{ start: 23, end: 23 }], snippet: 'selfdestruct(payable(owner));', graph_nodes: [], dependency_path: [], tool_output: null },
    verification: { llm_status: 'not_run', llm_explanation: null, evm_status: 'not_run', evm_details: null },
    is_mock: true,
  },
];

export const MOCK_HEALTH: Health = {
  status: 'degraded',
  contract_version: '1.0.0',
  analyzers: { mock: true },
};

const t0 = '2026-01-01T00:00:00Z';

export function mockEvents(upTo: number): StageEvent[] {
  const stages = ['received', 'parsing', 'static_analysis', 'ml_inference', 'evidence', 'llm_verification', 'evm_validation', 'reporting'] as const;
  const ev: StageEvent[] = [];
  stages.slice(0, upTo).forEach((stage) => {
    ev.push({ stage, status: 'started', at: t0, message: null });
    ev.push({ stage, status: 'completed', at: t0, message: `MOCK: ${stage} simulated` });
  });
  return ev;
}

export function mockJob(jobId: string, step: number, contract: ContractInfo = MOCK_CONTRACT): Job {
  const stages = ['received', 'parsing', 'static_analysis', 'ml_inference', 'evidence', 'llm_verification', 'evm_validation', 'reporting', 'done'] as const;
  const idx = Math.min(step, stages.length - 1);
  const done = idx === stages.length - 1;
  return {
    job_id: jobId,
    status: done ? 'completed' : 'running',
    stage: stages[idx] ?? 'done',
    progress: Math.round((idx / (stages.length - 1)) * 100),
    created_at: t0,
    updated_at: t0,
    contract,
    analyzers: ['mock'],
    events: mockEvents(idx),
    error: null,
    finding_count: done ? MOCK_FINDINGS.length : null,
  };
}

export function mockReport(jobId: string, contract: ContractInfo = MOCK_CONTRACT): AuditReport {
  return {
    report_id: `mock-report-${jobId}`,
    job_id: jobId,
    schema_version: '1.0.0',
    generated_at: t0,
    contract,
    analyzers: ['mock'],
    summary: { critical: 0, high: 1, medium: 1, low: 1, info: 0 },
    findings: MOCK_FINDINGS,
    contains_mock_data: true,
    report_hash: 'mock-not-a-real-hash',
    registry: null,
  };
}

export const MOCK_VERIFY: VerifyResponse = {
  valid: false,
  recomputed_hash: null,
  claimed_hash: null,
  registered: false,
  registry: null,
  chain_intact: false,
  reason: 'MOCK MODE — no backend contacted; nothing was verified.',
};
