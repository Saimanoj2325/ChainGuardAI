import { useId, useState } from 'react';
import { useApi } from '../api/ApiContext';
import type { VerifyRequest, VerifyResponse } from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { RegistryEntryView } from '../components/RegistryEntryView';
import { useReportMock } from '../lib/MockFlag';
import { readFileText } from '../lib/validation';

const MAX_REPORT_BYTES = 5 * 1024 * 1024;

type Verdict = 'valid' | 'tampered' | 'unverified';

export function verdictOf(r: VerifyResponse): Verdict {
  if (r.valid) return 'valid';
  if (r.recomputed_hash && r.claimed_hash && r.recomputed_hash !== r.claimed_hash) return 'tampered';
  return 'unverified';
}

const VERDICT_TEXT: Record<Verdict, { title: string; sub: string }> = {
  valid: { title: 'VALID — report integrity verified', sub: 'The recomputed hash matches the claimed hash and the registry check passed.' },
  tampered: { title: 'TAMPERED — report contents do not match its hash', sub: 'The report has been modified after it was generated. Do not trust it.' },
  unverified: { title: 'NOT VERIFIED', sub: 'The report could not be verified. See the reason below.' },
};

export function VerifyPage() {
  const api = useApi();
  const [text, setText] = useState('');
  const [hashOnly, setHashOnly] = useState('');
  const [parseError, setParseError] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<VerifyResponse | null>(null);
  const [submittedMock, setSubmittedMock] = useState(false);
  const taId = useId();
  const hashId = useId();

  useReportMock(submittedMock);

  async function onFile(f: File | undefined) {
    if (!f) return;
    if (f.size > MAX_REPORT_BYTES) {
      setParseError('Report file is larger than 5 MiB.');
      return;
    }
    setParseError(null);
    setText(await readFileText(f));
  }

  async function verify() {
    setError(null);
    setResult(null);
    setParseError(null);
    let body: VerifyRequest;
    let isMock = false;
    if (text.trim()) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch (e) {
        setParseError(`Not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
        return;
      }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        setParseError('The report must be a JSON object.');
        return;
      }
      const obj = parsed as Record<string, unknown>;
      isMock = obj.contains_mock_data === true || (Array.isArray(obj.findings) && obj.findings.some((f) => (f as { is_mock?: unknown })?.is_mock === true));
      body = { report: obj, report_hash: hashOnly.trim() || null };
    } else if (hashOnly.trim()) {
      body = { report: null, report_hash: hashOnly.trim() };
    } else {
      setParseError('Paste or upload a report JSON, or enter a report hash.');
      return;
    }
    setSubmittedMock(isMock);
    setBusy(true);
    try {
      setResult(await api.verifyReport(body));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  const verdict = result ? verdictOf(result) : null;

  return (
    <div className="stack">
      <section className="card" aria-labelledby="verify-title">
        <h2 id="verify-title" className="card__title">
          Verify an audit report
        </h2>
        <p className="muted small">
          Recomputes the report hash (canonical JSON, excluding <code>report_hash</code> and <code>registry</code>) and checks it against the local
          hash-chained registry.
        </p>
        <label htmlFor={taId} className="label">
          Report JSON
        </label>
        <textarea
          id={taId}
          className="textarea"
          rows={10}
          spellCheck={false}
          placeholder='{"report_id": "…", "report_hash": "…", …}'
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <div className="actions actions--inline">
          <label className="btn btn--ghost btn--sm file-btn">
            Upload report .json
            <input type="file" accept=".json,application/json" className="visually-hidden" aria-label="Upload report JSON file" onChange={(e) => void onFile(e.target.files?.[0])} />
          </label>
          {text && (
            <button type="button" className="btn btn--ghost btn--sm" onClick={() => setText('')}>
              Clear
            </button>
          )}
        </div>
        <label htmlFor={hashId} className="label">
          Report hash <span className="muted">(optional — or verify by hash alone)</span>
        </label>
        <input id={hashId} className="input" value={hashOnly} onChange={(e) => setHashOnly(e.target.value)} spellCheck={false} placeholder="sha256 hex" />
        {parseError && (
          <p className="field-error" role="alert">
            {parseError}
          </p>
        )}
        <div className="actions">
          <button type="button" className="btn btn--primary" onClick={() => void verify()} disabled={busy}>
            {busy ? 'Verifying…' : 'Verify report'}
          </button>
        </div>
      </section>

      {error !== null && <ErrorAlert title="Verification request failed" error={error} />}

      {result && verdict && (
        <section className={`card verdict verdict--${verdict}`} aria-labelledby="verdict-title" data-testid="verify-result" data-verdict={verdict}>
          <div className="verdict__head" role="status">
            <span className="verdict__icon" aria-hidden="true">
              {verdict === 'valid' ? '✓' : verdict === 'tampered' ? '✕' : '!'}
            </span>
            <div>
              <h2 id="verdict-title" className="verdict__title">
                {VERDICT_TEXT[verdict].title}
              </h2>
              <p className="small">{VERDICT_TEXT[verdict].sub}</p>
            </div>
          </div>
          <dl className="kv">
            <dt>Reason</dt>
            <dd data-testid="verify-reason">{result.reason}</dd>
            <dt>Hash match</dt>
            <dd>
              {result.recomputed_hash && result.claimed_hash
                ? result.recomputed_hash === result.claimed_hash
                  ? '✓ recomputed hash equals claimed hash'
                  : '✕ recomputed hash differs from claimed hash'
                : '—'}
            </dd>
            <dt>Claimed hash</dt>
            <dd>
              <code className="hash">{result.claimed_hash ?? '—'}</code>
            </dd>
            <dt>Recomputed hash</dt>
            <dd>
              <code className="hash">{result.recomputed_hash ?? '—'}</code>
            </dd>
            <dt>Registered</dt>
            <dd data-testid="verify-registered">{result.registered ? 'Yes — found in registry' : 'No — not found in registry'}</dd>
            <dt>Registry chain</dt>
            <dd data-testid="verify-chain">{result.chain_intact ? '✓ Chain intact' : '✕ Chain broken — registry may have been tampered with'}</dd>
          </dl>
          {result.registry && (
            <>
              <h3 className="subhead">Registry entry</h3>
              <RegistryEntryView entry={result.registry} />
            </>
          )}
        </section>
      )}
    </div>
  );
}
