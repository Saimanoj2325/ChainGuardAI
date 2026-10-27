import { useId, useRef, useState, type DragEvent, type KeyboardEvent } from 'react';
import { formatBytes } from '../lib/format';
import { MAX_UPLOAD_BYTES, validateSolidityFile } from '../lib/validation';

interface Props {
  onSubmit: (file: File) => void;
  busy?: boolean;
}

export function UploadPanel({ onSubmit, busy = false }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const hintId = useId();
  const errId = useId();

  function accept(f: File | undefined | null) {
    if (!f) return;
    const v = validateSolidityFile(f);
    if (!v.ok) {
      setFile(null);
      setError(v.reason);
      return;
    }
    setError(null);
    setFile(f);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    if (busy) return;
    const files = e.dataTransfer?.files;
    if (files && files.length > 1) {
      setFile(null);
      setError('Drop a single .sol file.');
      return;
    }
    accept(files?.[0]);
  }

  function onKey(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      inputRef.current?.click();
    }
  }

  return (
    <section className="card" aria-labelledby="upload-title">
      <h2 id="upload-title" className="card__title">
        Upload a Solidity contract
      </h2>
      <div
        className={`dropzone${dragging ? ' dropzone--active' : ''}${error ? ' dropzone--error' : ''}`}
        role="button"
        tabIndex={busy ? -1 : 0}
        aria-disabled={busy}
        aria-label="Choose or drop a .sol file"
        aria-describedby={`${hintId}${error ? ` ${errId}` : ''}`}
        data-testid="dropzone"
        onClick={() => !busy && inputRef.current?.click()}
        onKeyDown={onKey}
        onDragOver={(e) => {
          e.preventDefault();
          if (!busy) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <svg aria-hidden="true" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" />
        </svg>
        <p className="dropzone__main">
          Drag &amp; drop a <code>.sol</code> file, or <span className="link">browse</span>
        </p>
        <p id={hintId} className="muted small">
          One file, max {formatBytes(MAX_UPLOAD_BYTES)}. Source is analysed in an isolated sandbox.
        </p>
        <input
          ref={inputRef}
          type="file"
          accept=".sol"
          className="visually-hidden"
          data-testid="file-input"
          aria-label="Solidity file"
          tabIndex={-1}
          onChange={(e) => {
            accept(e.target.files?.[0]);
            e.target.value = '';
          }}
        />
      </div>

      {error && (
        <p id={errId} className="field-error" role="alert">
          {error}
        </p>
      )}

      {file && (
        <div className="file-row" data-testid="selected-file">
          <span className="file-row__icon" aria-hidden="true">
            ◆
          </span>
          <span className="file-row__name">{file.name}</span>
          <span className="muted">{formatBytes(file.size)}</span>
          <button type="button" className="btn btn--ghost btn--sm" onClick={() => setFile(null)} disabled={busy} aria-label={`Remove ${file.name}`}>
            Remove
          </button>
        </div>
      )}

      <div className="actions">
        <button type="button" className="btn btn--primary" disabled={!file || busy} onClick={() => file && onSubmit(file)}>
          {busy ? 'Submitting…' : 'Run security analysis'}
        </button>
      </div>
    </section>
  );
}
