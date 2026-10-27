import { useEffect, useState } from 'react';
import { ApiProvider } from './api/ApiContext';
import type { ApiClient } from './api/client';
import { HealthIndicator } from './components/HealthIndicator';
import { MockBanner } from './components/MockBanner';
import { MockFlagProvider, useMockFlag } from './lib/MockFlag';
import { AnalyzePage } from './pages/AnalyzePage';
import { VerifyPage } from './pages/VerifyPage';

type Route = 'analyze' | 'verify';

function routeFromHash(): Route {
  return window.location.hash.replace(/^#\/?/, '') === 'verify' ? 'verify' : 'analyze';
}

function Shell({ client, pollIntervalMs, healthIntervalMs }: { client: ApiClient; pollIntervalMs?: number; healthIntervalMs?: number }) {
  const [route, setRoute] = useState<Route>(routeFromHash);
  const { dataIsMock } = useMockFlag();

  useEffect(() => {
    const on = () => setRoute(routeFromHash());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);

  const showMock = client.kind === 'mock' || dataIsMock;

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      {showMock && (
        <MockBanner
          reason={
            client.kind === 'mock'
              ? 'Running with VITE_USE_MOCKS=true: no backend is contacted and every result is synthetic.'
              : 'The data shown contains mock findings (is_mock / contains_mock_data). Do not treat it as a real audit.'
          }
        />
      )}
      <header className="topbar">
        <div className="topbar__brand">
          <svg aria-hidden="true" width="26" height="26" viewBox="0 0 32 32">
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="none" stroke="currentColor" strokeWidth="2" />
            <path d="m11 16 3.5 3.5L21 13" fill="none" stroke="currentColor" strokeWidth="2" />
          </svg>
          <div>
            <div className="topbar__name">ChainGuard AI</div>
            <div className="topbar__tag">Evidence-grounded smart-contract auditing</div>
          </div>
        </div>
        <nav aria-label="Primary" className="topbar__nav">
          <a href="#/analyze" aria-current={route === 'analyze' ? 'page' : undefined}>
            Analyze
          </a>
          <a href="#/verify" aria-current={route === 'verify' ? 'page' : undefined}>
            Verify report
          </a>
        </nav>
        <HealthIndicator intervalMs={healthIntervalMs} />
      </header>
      <main id="main" className="main" tabIndex={-1}>
        {route === 'analyze' ? <AnalyzePage pollIntervalMs={pollIntervalMs} /> : <VerifyPage />}
      </main>
      <footer className="footer muted small">
        ChainGuard AI · findings are machine-generated and must be reviewed by a human auditor · registry is a local hash chain, not a public blockchain
      </footer>
    </>
  );
}

export function App(props: { client: ApiClient; pollIntervalMs?: number; healthIntervalMs?: number }) {
  return (
    <ApiProvider client={props.client}>
      <MockFlagProvider>
        <Shell {...props} />
      </MockFlagProvider>
    </ApiProvider>
  );
}
