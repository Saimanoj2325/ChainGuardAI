import { SEVERITIES, type AuditReport, type Finding, type Severity, type SeverityCounts } from '../api/types';

export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);

export type SortKey = 'severity' | 'confidence';

export function sortFindings(findings: readonly Finding[], key: SortKey): Finding[] {
  return [...findings].sort((a, b) => {
    if (key === 'confidence') {
      return b.confidence - a.confidence || severityRank(a.severity) - severityRank(b.severity);
    }
    return severityRank(a.severity) - severityRank(b.severity) || b.confidence - a.confidence;
  });
}

export function countBySeverity(findings: readonly Finding[]): SeverityCounts {
  const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity] += 1;
  return c;
}

/** True if any displayed data is mock — drives the MOCK DATA banner. */
export function containsMock(findings: readonly Finding[] | undefined, report?: Pick<AuditReport, 'contains_mock_data' | 'findings'> | null): boolean {
  if (findings?.some((f) => f.is_mock === true)) return true;
  if (report?.contains_mock_data === true) return true;
  if (report?.findings?.some((f) => f.is_mock === true)) return true;
  return false;
}
