import type { ApiConfig } from './config';
import type {
  AuditReport,
  FindingsResponse,
  Health,
  Job,
  Severity,
  SubmitResponse,
  VerifyRequest,
  VerifyResponse,
} from './types';

/** Error raised for any failed API interaction. status 0 = network/transport failure. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail?: string;
  constructor(message: string, status: number, detail?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

export interface ReportWithRaw {
  report: AuditReport;
  /** Exact JSON text returned by the server (used for byte-faithful download). */
  raw: string;
}

/** The surface the UI depends on. Implemented by HttpApiClient (real) and the mock client in src/mocks/. */
export interface ApiClient {
  readonly kind: 'http' | 'mock';
  readonly baseUrl: string;
  health(signal?: AbortSignal): Promise<Health>;
  submitAnalysis(file: File, signal?: AbortSignal): Promise<SubmitResponse>;
  getJob(jobId: string, signal?: AbortSignal): Promise<Job>;
  getFindings(jobId: string, severity?: Severity[], signal?: AbortSignal): Promise<FindingsResponse>;
  getReport(jobId: string, signal?: AbortSignal): Promise<ReportWithRaw>;
  getReportMarkdown(jobId: string, signal?: AbortSignal): Promise<string>;
  verifyReport(body: VerifyRequest, signal?: AbortSignal): Promise<VerifyResponse>;
}

async function errorFromResponse(res: Response): Promise<ApiError> {
  let message = `HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ''}`;
  let detail: string | undefined;
  try {
    const text = await res.text();
    if (text) {
      try {
        const body: unknown = JSON.parse(text);
        if (body && typeof body === 'object') {
          const b = body as Record<string, unknown>;
          if (typeof b.error === 'string') message = b.error;
          if (typeof b.detail === 'string') detail = b.detail;
          else if (b.detail !== undefined && b.detail !== null) detail = JSON.stringify(b.detail);
        }
      } catch {
        detail = text.slice(0, 500);
      }
    }
  } catch {
    /* ignore body read failures */
  }
  return new ApiError(message, res.status, detail);
}

export class HttpApiClient implements ApiClient {
  readonly kind = 'http' as const;
  readonly baseUrl: string;
  private readonly apiKey?: string;

  constructor(config: ApiConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.apiKey = config.apiKey;
  }

  private async request(path: string, init: RequestInit = {}, accept = 'application/json'): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set('Accept', accept);
    if (this.apiKey) headers.set('X-API-Key', this.apiKey);
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, { ...init, headers });
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') throw e;
      throw new ApiError(
        `Network error: could not reach the ChainGuard API at ${this.baseUrl}`,
        0,
        e instanceof Error ? e.message : String(e),
      );
    }
    if (!res.ok) throw await errorFromResponse(res);
    return res;
  }

  private async json<T>(path: string, init?: RequestInit): Promise<T> {
    const res = await this.request(path, init);
    try {
      return (await res.json()) as T;
    } catch {
      throw new ApiError('The API returned a response that is not valid JSON', res.status);
    }
  }

  health(signal?: AbortSignal): Promise<Health> {
    return this.json<Health>('/api/v1/health', { signal });
  }

  submitAnalysis(file: File, signal?: AbortSignal): Promise<SubmitResponse> {
    const form = new FormData();
    form.append('file', file, file.name);
    return this.json<SubmitResponse>('/api/v1/analyses', { method: 'POST', body: form, signal });
  }

  getJob(jobId: string, signal?: AbortSignal): Promise<Job> {
    return this.json<Job>(`/api/v1/analyses/${encodeURIComponent(jobId)}`, { signal });
  }

  getFindings(jobId: string, severity?: Severity[], signal?: AbortSignal): Promise<FindingsResponse> {
    const qs = new URLSearchParams();
    severity?.forEach((s) => qs.append('severity', s));
    const q = qs.toString();
    return this.json<FindingsResponse>(`/api/v1/analyses/${encodeURIComponent(jobId)}/findings${q ? `?${q}` : ''}`, {
      signal,
    });
  }

  async getReport(jobId: string, signal?: AbortSignal): Promise<ReportWithRaw> {
    const res = await this.request(`/api/v1/analyses/${encodeURIComponent(jobId)}/report?format=json`, { signal });
    const raw = await res.text();
    try {
      return { report: JSON.parse(raw) as AuditReport, raw };
    } catch {
      throw new ApiError('The report endpoint returned invalid JSON', res.status);
    }
  }

  async getReportMarkdown(jobId: string, signal?: AbortSignal): Promise<string> {
    const res = await this.request(
      `/api/v1/analyses/${encodeURIComponent(jobId)}/report?format=markdown`,
      { signal },
      'text/markdown, text/plain;q=0.9, */*;q=0.5',
    );
    return res.text();
  }

  verifyReport(body: VerifyRequest, signal?: AbortSignal): Promise<VerifyResponse> {
    return this.json<VerifyResponse>('/api/v1/reports/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    });
  }
}
