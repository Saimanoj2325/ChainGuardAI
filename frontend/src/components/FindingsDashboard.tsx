import { useEffect, useMemo, useState } from 'react';
import { SEVERITIES, type Finding, type Severity, type VulnClass } from '../api/types';
import { countBySeverity, sortFindings, type SortKey } from '../lib/findings';
import { formatPercent, humanize } from '../lib/format';
import { SeverityBadge, VerificationBadge } from './Badges';
import { FindingDetail } from './FindingDetail';

interface Props {
  findings: readonly Finding[];
  source?: string | null;
  filename?: string;
}

function toggle<T>(set: ReadonlySet<T>, v: T): Set<T> {
  const n = new Set(set);
  if (n.has(v)) n.delete(v);
  else n.add(v);
  return n;
}

export function FindingsDashboard({ findings, source, filename }: Props) {
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [classFilter, setClassFilter] = useState<Set<VulnClass>>(new Set());
  const [sortKey, setSortKey] = useState<SortKey>('severity');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const counts = useMemo(() => countBySeverity(findings), [findings]);
  const classes = useMemo(() => [...new Set(findings.map((f) => f.vuln_class))].sort(), [findings]);

  const visible = useMemo(() => {
    const filtered = findings.filter(
      (f) => (sevFilter.size === 0 || sevFilter.has(f.severity)) && (classFilter.size === 0 || classFilter.has(f.vuln_class)),
    );
    return sortFindings(filtered, sortKey);
  }, [findings, sevFilter, classFilter, sortKey]);

  useEffect(() => {
    if (!visible.some((f) => f.id === selectedId)) setSelectedId(visible[0]?.id ?? null);
  }, [visible, selectedId]);

  const selected = visible.find((f) => f.id === selectedId) ?? null;

  return (
    <section className="card" aria-labelledby="findings-title">
      <div className="card__head">
        <h2 id="findings-title" className="card__title">
          Findings <span className="muted">({findings.length})</span>
        </h2>
      </div>

      <div className="summary" role="list" aria-label="Findings by severity">
        {SEVERITIES.map((s) => (
          <div key={s} role="listitem" className={`summary__item sev-border--${s}`} data-testid={`count-${s}`}>
            <span className="summary__count">{counts[s]}</span>
            <span className="summary__label">{humanize(s)}</span>
          </div>
        ))}
      </div>

      {findings.length === 0 ? (
        <p className="empty">No findings were reported for this contract. This is not a guarantee of safety.</p>
      ) : (
        <>
          <div className="toolbar">
            <div className="chip-group" role="group" aria-label="Filter by severity">
              <span className="label">Severity</span>
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  type="button"
                  className={`chip chip--sev-${s}`}
                  aria-pressed={sevFilter.has(s)}
                  disabled={counts[s] === 0}
                  onClick={() => setSevFilter((p) => toggle(p, s))}
                >
                  {humanize(s)} <span className="chip__n">{counts[s]}</span>
                </button>
              ))}
            </div>
            <div className="chip-group" role="group" aria-label="Filter by vulnerability class">
              <span className="label">Class</span>
              {classes.map((c) => (
                <button key={c} type="button" className="chip" aria-pressed={classFilter.has(c)} onClick={() => setClassFilter((p) => toggle(p, c))}>
                  {humanize(c)}
                </button>
              ))}
            </div>
            <div className="toolbar__right">
              {(sevFilter.size > 0 || classFilter.size > 0) && (
                <button
                  type="button"
                  className="btn btn--ghost btn--sm"
                  onClick={() => {
                    setSevFilter(new Set());
                    setClassFilter(new Set());
                  }}
                >
                  Clear filters
                </button>
              )}
              <label className="select">
                <span className="label">Sort by</span>
                <select value={sortKey} onChange={(e) => setSortKey(e.target.value as SortKey)} aria-label="Sort findings">
                  <option value="severity">Severity</option>
                  <option value="confidence">Confidence</option>
                </select>
              </label>
            </div>
          </div>

          <div className="findings">
            <ul className="findings__list" aria-label="Findings list" data-testid="findings-list">
              {visible.map((f) => (
                <li key={f.id}>
                  <button
                    type="button"
                    className={`finding-row${f.id === selectedId ? ' finding-row--active' : ''}`}
                    aria-pressed={f.id === selectedId}
                    aria-label={`${f.severity} severity: ${f.title}, confidence ${formatPercent(f.confidence)}`}
                    data-testid="finding-row"
                    data-severity={f.severity}
                    onClick={() => setSelectedId(f.id)}
                  >
                    <SeverityBadge severity={f.severity} />
                    <span className="finding-row__main">
                      <span className="finding-row__title">{f.title}</span>
                      <span className="muted small">
                        {humanize(f.vuln_class)}
                        {f.function_name ? ` · ${f.function_name}()` : ''} · {formatPercent(f.confidence)}
                      </span>
                    </span>
                    <span className="finding-row__verif" aria-hidden="true">
                      <VerificationBadge kind="llm" status={f.verification.llm_status} />
                      <VerificationBadge kind="evm" status={f.verification.evm_status} />
                    </span>
                  </button>
                </li>
              ))}
              {visible.length === 0 && <li className="empty">No findings match the selected filters.</li>}
            </ul>
            <div className="findings__detail">{selected ? <FindingDetail finding={selected} source={source} filename={filename} /> : null}</div>
          </div>
        </>
      )}
    </section>
  );
}
