import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { JobProgress } from './JobProgress';
import type { Job } from '../api/types';

const baseJob: Job = {
  job_id: 'job-12345',
  status: 'running',
  stage: 'ml_inference',
  progress: 50,
  created_at: '2026-10-27T12:00:00Z',
  updated_at: '2026-10-27T12:01:00Z',
  contract: {
    filename: 'Bank.sol',
    sha256: 'abc123def456',
    size_bytes: 1024,
    contracts: ['Bank'],
  },
  analyzers: ['heuristic@1.0.0'],
  events: [
    { stage: 'received', status: 'completed', at: '2026-10-27T12:00:01Z', message: 'Received' },
    { stage: 'parsing', status: 'completed', at: '2026-10-27T12:00:05Z', message: 'Compiled successfully' },
    { stage: 'static_analysis', status: 'completed', at: '2026-10-27T12:00:10Z', message: '1 finding found' },
    { stage: 'ml_inference', status: 'started', at: '2026-10-27T12:00:15Z', message: 'Running GNN model' },
  ],
};

describe('JobProgress', () => {
  it('renders progress bar and current stage', () => {
    render(<JobProgress job={baseJob} />);

    expect(screen.getByText(/Bank\.sol/)).toBeInTheDocument();
    expect(screen.getByText(/job-12345/)).toBeInTheDocument();
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '50');
    expect(screen.getByText(/current stage:/i)).toHaveTextContent(/ML inference/i);
  });

  it('renders timeline with stage events and messages', () => {
    render(<JobProgress job={baseJob} />);

    expect(screen.getByText('Compiled successfully')).toBeInTheDocument();
    expect(screen.getByText('1 finding found')).toBeInTheDocument();
    expect(screen.getByText('Running GNN model')).toBeInTheDocument();
  });

  it('renders error alert when job status is failed', () => {
    const failedJob: Job = {
      ...baseJob,
      status: 'failed',
      error: 'Solidity compilation failed with syntax error',
    };
    render(<JobProgress job={failedJob} />);

    expect(screen.getByRole('alert')).toHaveTextContent(/Solidity compilation failed with syntax error/i);
  });
});
