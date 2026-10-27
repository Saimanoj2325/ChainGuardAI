import { useEffect, useMemo, useRef } from 'react';
import type { LineRange } from '../api/types';

interface Props {
  source: string;
  highlight: readonly LineRange[];
  filename?: string;
  /** Lines of context around highlighted ranges; null = render the full file. */
  context?: number | null;
}

export function isLineHighlighted(line: number, ranges: readonly LineRange[]): boolean {
  return ranges.some((r) => line >= Math.min(r.start, r.end) && line <= Math.max(r.start, r.end));
}

export function SourceViewer({ source, highlight, filename, context = null }: Props) {
  const lines = useMemo(() => source.replace(/\r\n?/g, '\n').split('\n'), [source]);
  const firstHl = useRef<HTMLTableRowElement>(null);

  const visible = useMemo(() => {
    if (context === null || highlight.length === 0) return lines.map((_, i) => i + 1);
    const keep = new Set<number>();
    for (const r of highlight) {
      const lo = Math.max(1, Math.min(r.start, r.end) - context);
      const hi = Math.min(lines.length, Math.max(r.start, r.end) + context);
      for (let i = lo; i <= hi; i++) keep.add(i);
    }
    return [...keep].sort((a, b) => a - b);
  }, [lines, highlight, context]);

  const outOfRange = highlight.filter((r) => Math.min(r.start, r.end) > lines.length);
  const firstLine = visible.find((n) => isLineHighlighted(n, highlight));

  useEffect(() => {
    const el = firstHl.current;
    if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [firstLine, source]);

  const label = highlight.length
    ? `Source of ${filename ?? 'contract'}, evidence on lines ${highlight.map((r) => (r.start === r.end ? r.start : `${r.start}–${r.end}`)).join(', ')}`
    : `Source of ${filename ?? 'contract'}`;

  return (
    <figure className="source" aria-label={label}>
      {filename && <figcaption className="source__caption">{filename}</figcaption>}
      {outOfRange.length > 0 && (
        <p className="field-error small">Some evidence lines are outside this file ({lines.length} lines) — source may differ from the analysed file.</p>
      )}
      <div className="source__scroll" tabIndex={0} role="region" aria-label="Source code">
        <table className="source__table">
          <tbody>
            {visible.map((n, idx) => {
              const hl = isLineHighlighted(n, highlight);
              const gap = idx > 0 && visible[idx - 1] !== n - 1;
              return (
                <tr
                  key={n}
                  ref={n === firstLine ? firstHl : undefined}
                  className={`${hl ? 'line line--evidence' : 'line'}${gap ? ' line--gap' : ''}`}
                  data-line={n}
                  data-highlighted={hl ? 'true' : 'false'}
                  aria-current={hl ? 'true' : undefined}
                >
                  <td className="line__no" aria-hidden="true">
                    {n}
                  </td>
                  <td className="line__code">
                    {hl && <span className="visually-hidden">Evidence line {n}: </span>}
                    <code>{lines[n - 1] || ' '}</code>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </figure>
  );
}
