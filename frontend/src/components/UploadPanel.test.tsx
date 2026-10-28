import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { UploadPanel } from './UploadPanel';

describe('UploadPanel', () => {
  it('renders upload area with guidance', () => {
    const onSubmit = vi.fn();
    render(<UploadPanel onSubmit={onSubmit} busy={false} />);

    expect(screen.getByText(/Drag & drop a/i)).toBeInTheDocument();
    expect(screen.getByText(/One file, max 512.0 KiB/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Run security analysis/i })).toBeDisabled();
  });

  it('allows selecting a .sol file and triggers submit on button click', () => {
    const onSubmit = vi.fn();
    render(<UploadPanel onSubmit={onSubmit} busy={false} />);

    const input = screen.getByTestId('file-input');
    const validFile = new File(['contract Token {}'], 'Token.sol', { type: 'text/plain' });

    fireEvent.change(input, { target: { files: [validFile] } });

    expect(screen.getByTestId('selected-file')).toBeInTheDocument();
    expect(screen.getByText('Token.sol')).toBeInTheDocument();

    const submitBtn = screen.getByRole('button', { name: /Run security analysis/i });
    expect(submitBtn).toBeEnabled();

    fireEvent.click(submitBtn);
    expect(onSubmit).toHaveBeenCalledWith(validFile);
  });

  it('rejects non-.sol file', () => {
    const onSubmit = vi.fn();
    render(<UploadPanel onSubmit={onSubmit} busy={false} />);

    const input = screen.getByTestId('file-input');
    const invalidFile = new File(['hello'], 'document.pdf', { type: 'application/pdf' });

    fireEvent.change(input, { target: { files: [invalidFile] } });

    expect(screen.getByRole('alert')).toHaveTextContent(/Only \.sol files are accepted/i);
    expect(screen.queryByTestId('selected-file')).not.toBeInTheDocument();
  });

  it('rejects oversized file exceeding 512 KiB', () => {
    const onSubmit = vi.fn();
    render(<UploadPanel onSubmit={onSubmit} busy={false} />);

    const input = screen.getByTestId('file-input');
    // Create oversized file (> 512 KiB)
    const largeBlob = new Blob(['x'.repeat(600 * 1024)]);
    const oversizedFile = new File([largeBlob], 'Huge.sol');

    fireEvent.change(input, { target: { files: [oversizedFile] } });

    expect(screen.getByRole('alert')).toHaveTextContent(/the limit is 512 KiB/i);
    expect(screen.queryByTestId('selected-file')).not.toBeInTheDocument();
  });
});
