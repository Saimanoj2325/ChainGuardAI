import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { FindingsDashboard } from './FindingsDashboard';
import type { Finding } from '../api/types';

const sampleFindings: Finding[] = [
  {
    id: 'f-1',
    vuln_class: 'reentrancy',
    title: 'State change after external call',
    severity: 'critical',
    confidence: 0.95,
    detectors: ['slither', 'heuristic'],
    function_name: 'withdraw',
    contract_name: 'Bank',
    description: 'Contract updates balance after external call',
    recommendation: 'Use Checks-Effects-Interactions pattern',
    evidence: {
      lines: [{ start: 10, end: 12 }],
      snippet: 'msg.sender.call{value: amount}("");\nbalances[msg.sender] = 0;',
      graph_nodes: ['CFG:withdraw#1', 'DFG:balances'],
      dependency_path: ['call -> state update'],
    },
    verification: {
      llm_status: 'supported',
      llm_explanation: 'Classic reentrancy pattern confirmed.',
      evm_status: 'confirmed',
      evm_details: 'Reentrancy exploit executed successfully.',
    },
    is_mock: false,
  },
  {
    id: 'f-2',
    vuln_class: 'tx_origin',
    title: 'Use of tx.origin for authentication',
    severity: 'medium',
    confidence: 0.8,
    detectors: ['heuristic'],
    function_name: 'transferOwnership',
    contract_name: 'Ownable',
    description: 'tx.origin is vulnerable to phishing',
    recommendation: 'Use msg.sender instead of tx.origin',
    evidence: {
      lines: [{ start: 20, end: 20 }],
      snippet: 'require(tx.origin == owner);',
      graph_nodes: [],
      dependency_path: [],
    },
    verification: {
      llm_status: 'supported',
      evm_status: 'not_applicable',
    },
    is_mock: false,
  },
];

describe('FindingsDashboard', () => {
  it('renders severity summary counts and findings list', () => {
    render(<FindingsDashboard findings={sampleFindings} />);

    expect(screen.getByTestId('count-critical')).toHaveTextContent('1');
    expect(screen.getByTestId('count-medium')).toHaveTextContent('1');
    expect(screen.getByTestId('count-high')).toHaveTextContent('0');

    const rows = screen.getAllByTestId('finding-row');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByText('State change after external call')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Use of tx.origin for authentication')).toBeInTheDocument();
  });

  it('filters by severity when clicking a severity chip', () => {
    render(<FindingsDashboard findings={sampleFindings} />);

    // Click Critical filter chip
    const criticalChip = screen.getByRole('button', { name: /Critical 1/i });
    fireEvent.click(criticalChip);

    const rows = screen.getAllByTestId('finding-row');
    expect(rows).toHaveLength(1);
    expect(within(rows[0]!).getByText('State change after external call')).toBeInTheDocument();
  });

  it('shows empty state when no findings match', () => {
    render(<FindingsDashboard findings={[]} />);
    expect(screen.getByText(/No findings were reported for this contract/i)).toBeInTheDocument();
  });
});
