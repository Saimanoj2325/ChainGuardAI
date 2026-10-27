import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { HttpApiClient, type ApiClient } from './api/client';
import { mocksEnabled, readApiConfig } from './api/config';
import './styles/global.css';

async function makeClient(): Promise<ApiClient> {
  if (mocksEnabled()) {
    // Mock code is only loaded when explicitly enabled; real mode never falls back to it.
    const { MockApiClient } = await import('./mocks/mockClient');
    return new MockApiClient();
  }
  return new HttpApiClient(readApiConfig());
}

void makeClient().then((client) => {
  const el = document.getElementById('root');
  if (!el) throw new Error('#root missing');
  createRoot(el).render(
    <StrictMode>
      <App client={client} />
    </StrictMode>,
  );
});
