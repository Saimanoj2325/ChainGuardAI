import { useEffect, useState } from 'react';
import { useApi } from '../api/ApiContext';
import type { Health } from '../api/types';
import { humanize } from '../lib/format';

type State = { kind: 'loading' } | { kind: 'ok'; health: Health } | { kind: 'error'; message: string };

export function HealthIndicator({ intervalMs = 30000 }: { intervalMs?: number }) {
  const api = useApi();
  const [state, setState] = useState<State>({ kind: 'loading' });

  useEffect(() => {
    let alive = true;
    const ctrl = new AbortController();
    const load = () =>
      api
        .health(ctrl.signal)
        .then((h) => alive && setState({ kind: 'ok', health: h }))
        .catch((e: unknown) => {
          if (!alive || (e instanceof DOMException && e.name === 'AbortError')) return;
          setState({ kind: 'error', message: e instanceof Error ? e.message : String(e) });
        });
    void load();
    const t = setInterval(load, intervalMs);
    return () => {
      alive = false;
      ctrl.abort();
      clearInterval(t);
    };
  }, [api, intervalMs]);

  const tone = state.kind === 'ok' ? state.health.status : state.kind === 'error' ? 'down' : 'loading';
  const label =
    state.kind === 'loading' ? 'Checking API…' : state.kind === 'error' ? 'API unreachable' : state.health.status === 'ok' ? 'API healthy' : 'API degraded';

  return (
    <details className={`health health--${tone}`} data-testid="health">
      <summary aria-label={`Backend status: ${label}. Show analyzer availability.`}>
        <span className="health__dot" aria-hidden="true" />
        {label}
      </summary>
      <div className="health__panel">
        <div className="muted small">{api.kind === 'mock' ? 'Mock API (no backend)' : api.baseUrl}</div>
        {state.kind === 'error' && <p className="field-error">{state.message}</p>}
        {state.kind === 'ok' && (
          <>
            <div className="small">Contract version {state.health.contract_version}</div>
            <ul className="health__list" aria-label="Analyzer availability">
              {Object.entries(state.health.analyzers).map(([name, available]) => (
                <li key={name} data-available={available}>
                  <span aria-hidden="true">{available ? '●' : '○'}</span> {humanize(name)}
                  <span className="muted"> — {available ? 'available' : 'unavailable'}</span>
                </li>
              ))}
              {Object.keys(state.health.analyzers).length === 0 && <li className="muted">No analyzers reported</li>}
            </ul>
          </>
        )}
      </div>
    </details>
  );
}
