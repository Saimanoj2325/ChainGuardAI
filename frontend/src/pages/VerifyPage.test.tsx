import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { VerifyPage } from './VerifyPage';
import { ApiProvider } from '../api/ApiContext';
import type { ApiClient } from '../api/client';
import { MockFlagProvider } from '../lib/MockFlag';

function renderWithApi(client: ApiClient) {
  return render(
    <ApiProvider client={client}>
      <MockFlagProvider>
        <VerifyPage />
      </MockFlagProvider>
    </ApiProvider>
  );
}

describe('VerifyPage', () => {
  it('shows error if verifying with empty fields', async () => {
    const mockClient = {
      kind: 'real',
      verifyReport: vi.fn(),
    } as unknown as ApiClient;

    renderWithApi(mockClient);

    const verifyBtn = screen.getByRole('button', { name: /Verify report/i });
    fireEvent.click(verifyBtn);

    expect(screen.getByRole('alert')).toHaveTextContent(/Paste or upload a report JSON/i);
    expect(mockClient.verifyReport).not.toHaveBeenCalled();
  });

  it('verifies report JSON successfully', async () => {
    const mockClient = {
      kind: 'real',
      verifyReport: vi.fn().mockResolvedValue({
        valid: true,
        recomputed_hash: 'abc123hash',
        claimed_hash: 'abc123hash',
        registered: true,
        registry: {
          index: 4,
          report_hash: 'abc123hash',
          prev_entry_hash: '0000',
          entry_hash: 'def456',
          timestamp: '2026-10-27T12:00:00Z',
        },
        chain_intact: true,
        reason: 'Report hash matches claimed hash and is registered at index 4.',
      }),
    } as unknown as ApiClient;

    renderWithApi(mockClient);

    const textarea = screen.getByPlaceholderText(/\{"report_id":/i);
    fireEvent.change(textarea, { target: { value: JSON.stringify({ report_id: 'rep-1', report_hash: 'abc123hash' }) } });

    const verifyBtn = screen.getByRole('button', { name: /Verify report/i });
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(screen.getByTestId('verify-result')).toBeInTheDocument();
    });

    expect(screen.getByText(/VALID — report integrity verified/i)).toBeInTheDocument();
    expect(screen.getByTestId('verify-registered')).toHaveTextContent(/Yes — found in registry/i);
    expect(screen.getByTestId('verify-chain')).toHaveTextContent(/Chain intact/i);
  });

  it('flags tampered report when recomputed hash does not match', async () => {
    const mockClient = {
      kind: 'real',
      verifyReport: vi.fn().mockResolvedValue({
        valid: false,
        recomputed_hash: 'different_hash_after_tampering',
        claimed_hash: 'original_hash',
        registered: false,
        registry: null,
        chain_intact: true,
        reason: 'Recomputed hash does not match claimed hash in report.',
      }),
    } as unknown as ApiClient;

    renderWithApi(mockClient);

    const textarea = screen.getByPlaceholderText(/\{"report_id":/i);
    fireEvent.change(textarea, { target: { value: JSON.stringify({ report_id: 'rep-1', report_hash: 'original_hash' }) } });

    const verifyBtn = screen.getByRole('button', { name: /Verify report/i });
    fireEvent.click(verifyBtn);

    await waitFor(() => {
      expect(screen.getByTestId('verify-result')).toBeInTheDocument();
    });

    expect(screen.getByText(/TAMPERED — report contents do not match its hash/i)).toBeInTheDocument();
  });
});
