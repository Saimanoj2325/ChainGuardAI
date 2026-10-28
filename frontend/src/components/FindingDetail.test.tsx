import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { FindingDetail } from './FindingDetail';
import type { Finding } from '../api/types';

const finding: Finding = {
  id: 'finding-001',
  vuln_class: 'reentrancy',
  title: 'Classic reentrancy in withdraw()',
  severity: 'critical',
  confidence: 0.92,
  detectors: ['slither', 'gnn'],
  contract_name: 'EtherBank',
  function_name: 'withdraw',
  description: 'Balances modified after transferring ether to external caller.',
  recommendation: 'Update balance before calling external address or use ReentrancyGuard.',
  evidence: {
    lines: [{ start: 15, end: 17 }],
    snippet: 'msg.sender.call{value: amount}("");\nbalances[msg.sender] = 0;',
    graph_nodes: ['CFG:withdraw#3', 'DFG:balances'],
    dependency_path: ['call -> state update'],
    tool_output: 'Slither detector: reentrancy-eth',
  },
  verification: {
    llm_status: 'supported',
    llm_explanation: 'External call before state write confirmed.',
    evm_status: 'confirmed',
    evm_details: 'Exploit transaction reverted with drain condition reproduced.',
  },
  is_mock: false,
};

describe('FindingDetail', () => {
  it('renders title, location, and severity badges', () => {
    render(<FindingDetail finding={finding} />);

    expect(screen.getByText('Classic reentrancy in withdraw()')).toBeInTheDocument();
    expect(screen.getByText('EtherBank.withdraw')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText(/92%/i)).toBeInTheDocument();
  });

  it('renders description, recommendation and evidence', () => {
    render(<FindingDetail finding={finding} />);

    expect(screen.getByText(/Balances modified after transferring/i)).toBeInTheDocument();
    expect(screen.getByText(/Update balance before calling/i)).toBeInTheDocument();
    expect(screen.getByTestId('snippet')).toHaveTextContent(/msg\.sender\.call/);
    expect(screen.getByText('CFG:withdraw#3')).toBeInTheDocument();
  });

  it('renders verification explanation and evm details', () => {
    render(<FindingDetail finding={finding} />);

    expect(screen.getByText(/External call before state write confirmed\./i)).toBeInTheDocument();
    expect(screen.getByText(/Exploit transaction reverted/i)).toBeInTheDocument();
  });
});
