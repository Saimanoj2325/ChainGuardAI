import type { Finding } from '../api/types';
import { formatPercent, humanize } from '../lib/format';
import { DetectorBadge, SeverityBadge, VerificationBadge, VulnClassTag } from './Badges';
import { SourceViewer } from './SourceViewer';

export function FindingDetail({ finding, source, filename }: { finding: Finding; source?: string | null; filename?: string }) {
  const ev = finding.evidence ?? { lines: [], snippet: '', graph_nodes: [], dependency_path: [] };
  const v = finding.verification ?? { llm_status: 'not_run', evm_status: 'not_run' };
  const lines = ev.lines ?? [];
  const location = [finding.contract_name, finding.function_name].filter(Boolean).join('.');

  return (
    <article className="detail" aria-labelledby={`finding-${finding.id}-title`} data-testid="finding-detail">
      <header className="detail__head">
        <div className="detail__badges">
          <SeverityBadge severity={finding.severity} />
          <VulnClassTag value={finding.vuln_class} />
          {finding.is_mock && <span className="badge badge--mock">MOCK</span>}
        </div>
        <h3 id={`finding-${finding.id}-title`} className="detail__title">
          {finding.title}
        </h3>
        {location && (
          <p className="muted small">
            in <code>{location}</code>
            {lines.length > 0 && <> · lines {lines.map((r) => (r.start === r.end ? r.start : `${r.start}–${r.end}`)).join(', ')}</>}
          </p>
        )}
      </header>

      <div className="detail__grid">
        <div>
          <div className="label">Confidence</div>
          <div className="confidence" aria-label={`Confidence ${formatPercent(finding.confidence)}`}>
            <div className="confidence__track" aria-hidden="true">
              <div className="confidence__fill" style={{ width: formatPercent(finding.confidence) }} />
            </div>
            <span>{formatPercent(finding.confidence)}</span>
          </div>
        </div>
        <div>
          <div className="label">Detectors</div>
          <div className="chips">
            {finding.detectors.map((d) => (
              <DetectorBadge key={d} detector={d} />
            ))}
          </div>
        </div>
      </div>

      <section className="detail__section">
        <h4>Description</h4>
        <p>{finding.description}</p>
        {finding.recommendation && (
          <>
            <h4>Recommendation</h4>
            <p>{finding.recommendation}</p>
          </>
        )}
      </section>

      <section className="detail__section" aria-label="Verification">
        <h4>Verification</h4>
        <div className="verif-grid">
          <div className="verif-card">
            <VerificationBadge kind="llm" status={v.llm_status} />
            {v.llm_explanation ? <p className="small">{v.llm_explanation}</p> : <p className="muted small">No LLM explanation.</p>}
          </div>
          <div className="verif-card">
            <VerificationBadge kind="evm" status={v.evm_status} />
            {v.evm_details ? <pre className="pre small">{v.evm_details}</pre> : <p className="muted small">No EVM details.</p>}
          </div>
        </div>
      </section>

      <section className="detail__section" aria-label="Evidence">
        <h4>Evidence</h4>
        {source ? (
          <SourceViewer source={source} highlight={lines} filename={filename} context={null} />
        ) : (
          <p className="muted small">Original source not available in this session — showing the snippet only.</p>
        )}
        {ev.snippet && (
          <>
            <div className="label">Snippet</div>
            <pre className="pre" data-testid="snippet">
              <code>{ev.snippet}</code>
            </pre>
          </>
        )}
        {ev.graph_nodes.length > 0 && (
          <>
            <div className="label">Graph nodes</div>
            <div className="chips">
              {ev.graph_nodes.map((n) => (
                <code key={n} className="chip-code">
                  {n}
                </code>
              ))}
            </div>
          </>
        )}
        {ev.dependency_path.length > 0 && (
          <>
            <div className="label">Dependency path</div>
            <ol className="path" aria-label="Dependency path">
              {ev.dependency_path.map((step, i) => (
                <li key={i}>
                  <span className="path__n" aria-hidden="true">
                    {i + 1}
                  </span>
                  <code>{step}</code>
                </li>
              ))}
            </ol>
          </>
        )}
        {ev.tool_output && (
          <details className="raw">
            <summary>Raw tool output</summary>
            <pre className="pre small">{ev.tool_output}</pre>
          </details>
        )}
        {!ev.snippet && lines.length === 0 && ev.graph_nodes.length === 0 && ev.dependency_path.length === 0 && !ev.tool_output && (
          <p className="field-error small">No evidence attached to this finding — treat with caution.</p>
        )}
      </section>
      <p className="muted small">Finding ID {finding.id} · class {humanize(finding.vuln_class)}</p>
    </article>
  );
}
