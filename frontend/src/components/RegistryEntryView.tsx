import type { RegistryEntry } from '../api/types';
import { formatDateTime } from '../lib/format';

export function RegistryEntryView({ entry }: { entry: RegistryEntry }) {
  return (
    <div className="registry" data-testid="registry-entry">
      <dl className="kv">
        <dt>Index</dt>
        <dd>#{entry.index}</dd>
        <dt>Timestamp</dt>
        <dd>
          <time dateTime={entry.timestamp}>{formatDateTime(entry.timestamp)}</time>
        </dd>
        <dt>Report hash</dt>
        <dd>
          <code className="hash">{entry.report_hash}</code>
        </dd>
        <dt>Entry hash</dt>
        <dd>
          <code className="hash">{entry.entry_hash}</code>
        </dd>
        <dt>Previous entry</dt>
        <dd>
          <code className="hash">{entry.prev_entry_hash}</code>
        </dd>
      </dl>
      <p className="muted small">Local append-only hash-chained registry — not a public blockchain.</p>
    </div>
  );
}
