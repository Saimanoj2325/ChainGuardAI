import { useCallback, useEffect, useRef, useState } from 'react';
import { useApi } from '../api/ApiContext';
import type { ReportWithRaw } from '../api/client';
import type { Finding, Job } from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { FindingsDashboard } from '../components/FindingsDashboard';
import { JobProgress } from '../components/JobProgress';
import { ReportPanel } from '../components/ReportPanel';
import { UploadPanel } from '../components/UploadPanel';
import { containsMock } from '../lib/findings';
import { useReportMock } from '../lib/MockFlag';
import { readFileText } from '../lib/validation';

type Phase = 'idle' | 'submitting' | 'polling' | 'loading-results' | 'done' | 'failed';

export function AnalyzePage({ pollIntervalMs = 1500 }: { pollIntervalMs?: number }) {
  const api = useApi();
  const [phase, setPhase] = useState<Phase>('idle');
  const [submitError, setSubmitError] = useState<unknown>(null);
  const [pollError, setPollError] = useState<unknown>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [findingsError, setFindingsError] = useState<unknown>(null);
  const [report, setReport] = useState<ReportWithRaw | null>(null);
  const [reportError, setReportError] = useState<unknown>(null);
  const [source, setSource] = useState<string | null>(null);
  const [filename, setFilename] = useState<string | undefined>();
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const ctrl = useRef<AbortController | null>(null);

  useReportMock(containsMock(findings ?? undefined, report?.report));

  const stop = () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    ctrl.current?.abort();
  };
  useEffect(() => stop, []);

  const loadResults = useCallback(
    async (id: string) => {
      setPhase('loading-results');
      const [f, r] = await Promise.allSettled([api.getFindings(id), api.getReport(id)]);
      if (f.status === 'fulfilled') setFindings(f.value.findings);
      else setFindingsError(f.reason);
      if (r.status === 'fulfilled') setReport(r.value);
      else setReportError(r.reason);
      setPhase('done');
    },
    [api],
  );

  const poll = useCallback(
    async (id: string) => {
      ctrl.current = new AbortController();
      try {
        const j = await api.getJob(id, ctrl.current.signal);
        setJob(j);
        setPollError(null);
        if (j.status === 'completed') {
          await loadResults(id);
          return;
        }
        if (j.status === 'failed') {
          setPhase('failed');
          return;
        }
        timer.current = setTimeout(() => void poll(id), pollIntervalMs);
      } catch (e) {
        if (e instanceof DOMException && e.name === 'AbortError') return;
        setPollError(e);
      }
    },
    [api, loadResults, pollIntervalMs],
  );

  async function submit(file: File) {
    stop();
    setSubmitError(null);
    setPollError(null);
    setJob(null);
    setFindings(null);
    setFindingsError(null);
    setReport(null);
    setReportError(null);
    setPhase('submitting');
    setFilename(file.name);
    try {
      setSource(await readFileText(file));
    } catch {
      setSource(null);
    }
    try {
      const res = await api.submitAnalysis(file);
      setJobId(res.job_id);
      setPhase('polling');
      void poll(res.job_id);
    } catch (e) {
      setSubmitError(e);
      setPhase('idle');
    }
  }

  function reset() {
    stop();
    setPhase('idle');
    setJob(null);
    setJobId(null);
    setFindings(null);
    setReport(null);
    setSource(null);
    setSubmitError(null);
    setPollError(null);
    setFindingsError(null);
    setReportError(null);
  }

  const busy = phase === 'submitting' || phase === 'polling' || phase === 'loading-results';

  return (
    <div className="stack">
      {phase === 'idle' || phase === 'submitting' ? (
        <UploadPanel onSubmit={(f) => void submit(f)} busy={phase === 'submitting'} />
      ) : (
        <div className="actions actions--between">
          <span className="muted small">
            Analysing <code>{filename}</code>
          </span>
          <button type="button" className="btn btn--ghost" onClick={reset} disabled={phase === 'loading-results'}>
            {busy ? 'Cancel & start over' : 'Analyse another contract'}
          </button>
        </div>
      )}
      {submitError !== null && <ErrorAlert title="Submission failed" error={submitError} />}
      {pollError !== null && jobId && (
        <ErrorAlert
          title="Lost contact with the analysis job"
          error={pollError}
          onRetry={() => {
            setPollError(null);
            void poll(jobId);
          }}
        />
      )}
      {job && <JobProgress job={job} />}
      {phase === 'loading-results' && (
        <p className="muted" role="status">
          Loading results…
        </p>
      )}
      {findingsError !== null && <ErrorAlert title="Could not load findings" error={findingsError} />}
      {findings && <FindingsDashboard findings={findings} source={source} filename={filename} />}
      {reportError !== null && <ErrorAlert title="Could not load the report" error={reportError} />}
      {report && jobId && <ReportPanel jobId={jobId} data={report} />}
    </div>
  );
}
