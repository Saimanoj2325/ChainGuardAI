import { useState } from 'react';
import { useApi } from '../api/ApiContext';
import type { ReportWithRaw } from '../api/client';
import { downloadText } from '../lib/download';
import { formatDateTime } from '../lib/format';
import { CopyButton } from './CopyButton';
import { ErrorAlert } from './ErrorAlert';
import { RegistryEntryView } from './RegistryEntryView';

export function ReportPanel({ jobId, data }: { jobId: string; data: ReportWithRaw }) {
  const api = useApi();
  const { report, raw } = data;
  const [mdBusy, setMdBusy] = useState(false);
  const [mdError, setMdError] = useState<unknown>(null);

  async function downloadMarkdown() {
    setMdBusy(true);
    setMdError(null);
    try {
      const md = await api.getReportMarkdown(jobId);
      downloadText(`chainguard-report-${jobId}.md`, md, 'text/markdown');
    } catch (e) {
      setMdError(e);
    } finally {
      setMdBusy(false);
    }
  }

  return (
    <section className="card" aria-labelledby="report-title">
      <div className="card__head">
        <h2 id="report-title" className="card__title">
          Audit report
        </h2>
        <div className="actions actions--inline">
          <button type="button" className="btn" onClick={() => downloadText(`chainguard-report-${jobId}.json`, raw, 'application/json')}>
            Download JSON
          </button>
          <button type="button" className="btn" onClick={() => void downloadMarkdown()} disabled={mdBusy}>
            {mdBusy ? 'Preparing…' : 'Download Markdown'}
          </button>
        </div>
      </div>
      {mdError !== null && <ErrorAlert title="Markdown report download failed" error={mdError} />}
      <dl className="kv">
        <dt>Report hash</dt>
        <dd className="hash-row">
          <code className="hash" data-testid="report-hash">
            {report.report_hash}
          </code>
          <CopyButton text={report.report_hash} label="Copy hash" />
        </dd>
        <dt>Report ID</dt>
        <dd>
          <code>{report.report_id}</code>
        </dd>
        <dt>Generated</dt>
        <dd>{formatDateTime(report.generated_at)}</dd>
        <dt>Contract</dt>
        <dd>
          <code>{report.contract.filename}</code> · sha256 <code className="hash">{report.contract.sha256}</code>
          {report.contract.solc_version && <> · solc {report.contract.solc_version}</>}
        </dd>
        <dt>Analyzers</dt>
        <dd>{report.analyzers.length ? report.analyzers.join(', ') : '—'}</dd>
        <dt>Schema</dt>
        <dd>{report.schema_version}</dd>
      </dl>
      <h3 className="subhead">Registry entry</h3>
      {report.registry ? (
        <RegistryEntryView entry={report.registry} />
      ) : (
        <p className="muted small" data-testid="registry-missing">
          This report has not been appended to the registry.
        </p>
      )}
    </section>
  );
}
