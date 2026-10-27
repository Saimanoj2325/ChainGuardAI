import { ApiError } from '../api/client';

export function ErrorAlert({ title, error, onRetry }: { title: string; error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : String(error);
  const detail = error instanceof ApiError ? error.detail : undefined;
  const status = error instanceof ApiError && error.status > 0 ? error.status : undefined;
  return (
    <div className="alert alert--error" role="alert">
      <div className="alert__title">{title}</div>
      <div>
        {status !== undefined && <code className="alert__status">HTTP {status}</code>} {msg}
      </div>
      {detail && <pre className="alert__detail">{detail}</pre>}
      {onRetry && (
        <button type="button" className="btn btn--ghost" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
