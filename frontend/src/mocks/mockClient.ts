import { ApiError, type ApiClient, type ReportWithRaw } from '../api/client';
import type { ContractInfo, FindingsResponse, Health, Job, Severity, SubmitResponse, VerifyRequest, VerifyResponse } from '../api/types';
import { MOCK_FINDINGS, MOCK_HEALTH, MOCK_VERIFY, mockJob, mockReport } from './fixtures';

/** In-memory fake API used ONLY when VITE_USE_MOCKS=true. Never used as a fallback. */
export class MockApiClient implements ApiClient {
  readonly kind = 'mock' as const;
  readonly baseUrl = 'mock://local';
  private jobs = new Map<string, { step: number; contract: ContractInfo }>();
  private seq = 0;

  private delay<T>(v: T, ms = 250): Promise<T> {
    return new Promise((r) => setTimeout(() => r(v), ms));
  }

  health(): Promise<Health> {
    return this.delay(MOCK_HEALTH);
  }

  submitAnalysis(file: File): Promise<SubmitResponse> {
    const id = `mock-job-${++this.seq}`;
    const contract: ContractInfo = { filename: file.name, sha256: '(mock — not computed)', size_bytes: file.size, solc_version: null, contracts: [] };
    this.jobs.set(id, { step: 0, contract });
    return this.delay({ job_id: id, status: 'queued', contract });
  }

  getJob(jobId: string): Promise<Job> {
    const j = this.jobs.get(jobId);
    if (!j) return Promise.reject(new ApiError('job not found (mock)', 404));
    j.step += 1;
    return this.delay(mockJob(jobId, j.step, j.contract));
  }

  getFindings(jobId: string, severity?: Severity[]): Promise<FindingsResponse> {
    const findings = severity?.length ? MOCK_FINDINGS.filter((f) => severity.includes(f.severity)) : MOCK_FINDINGS;
    return this.delay({ job_id: jobId, findings });
  }

  getReport(jobId: string): Promise<ReportWithRaw> {
    const report = mockReport(jobId, this.jobs.get(jobId)?.contract);
    return this.delay({ report, raw: JSON.stringify(report, null, 2) });
  }

  getReportMarkdown(jobId: string): Promise<string> {
    return this.delay(`# MOCK REPORT — not a real analysis\n\nJob ${jobId}. All findings below are synthetic.\n\n${MOCK_FINDINGS.map((f) => `- **${f.severity}** ${f.title}`).join('\n')}\n`);
  }

  verifyReport(_body: VerifyRequest): Promise<VerifyResponse> {
    return this.delay(MOCK_VERIFY);
  }
}
