import { JOB_STAGES, type Job, type JobStage, type StageEvent } from '../api/types';
import { formatDateTime, humanize } from '../lib/format';

type StageState = 'pending' | 'started' | 'completed' | 'skipped' | 'failed';

const STAGE_LABEL: Record<JobStage, string> = {
  received: 'Received',
  parsing: 'Parsing & compilation',
  static_analysis: 'Static analysis',
  ml_inference: 'ML inference',
  evidence: 'Evidence extraction',
  llm_verification: 'LLM verification',
  evm_validation: 'EVM validation',
  reporting: 'Report & registry',
  done: 'Done',
};

function stageInfo(job: Job, stage: JobStage): { state: StageState; event?: StageEvent; messages: StageEvent[] } {
  const evs = (job.events ?? []).filter((e) => e.stage === stage);
  const last = evs[evs.length - 1];
  let state: StageState = last ? last.status : 'pending';
  if (stage === 'done' && job.status === 'completed') state = 'completed';
  if (!last && job.stage === stage && job.status === 'running') state = 'started';
  return { state, event: last, messages: evs.filter((e) => e.message) };
}

const ICON: Record<StageState, string> = {
  pending: '○',
  started: '◐',
  completed: '✓',
  skipped: '↷',
  failed: '✕',
};

export function JobProgress({ job }: { job: Job }) {
  const pct = Math.max(0, Math.min(100, job.progress));
  return (
    <section className="card" aria-labelledby="progress-title">
      <div className="card__head">
        <h2 id="progress-title" className="card__title">
          Analysis progress
        </h2>
        <span className={`status-pill status-pill--${job.status}`} data-testid="job-status">
          {humanize(job.status)}
        </span>
      </div>
      <p className="muted small">
        <code>{job.contract.filename}</code> · job <code>{job.job_id}</code>
      </p>
      <div
        className={`progress progress--${job.status}`}
        role="progressbar"
        aria-label="Analysis progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-valuetext={`${pct}% — ${STAGE_LABEL[job.stage]}`}
      >
        <div className="progress__bar" style={{ width: `${pct}%` }} />
      </div>
      <p className="small" aria-live="polite">
        {pct}% · current stage: <strong>{STAGE_LABEL[job.stage]}</strong>
      </p>

      {job.status === 'failed' && (
        <div className="alert alert--error" role="alert">
          <div className="alert__title">Analysis failed</div>
          <div>{job.error ?? 'The backend reported a failure without an error message.'}</div>
        </div>
      )}

      <ol className="timeline" aria-label="Pipeline stages">
        {JOB_STAGES.map((stage) => {
          const { state, event, messages } = stageInfo(job, stage);
          return (
            <li key={stage} className={`timeline__item timeline__item--${state}`} data-stage={stage} data-state={state}>
              <span className="timeline__icon" aria-hidden="true">
                {ICON[state]}
              </span>
              <div className="timeline__body">
                <div className="timeline__row">
                  <span className="timeline__label">{STAGE_LABEL[stage]}</span>
                  <span className="timeline__state">{state === 'pending' ? 'Pending' : humanize(state)}</span>
                  {event && <time className="muted small" dateTime={event.at}>{formatDateTime(event.at)}</time>}
                </div>
                {messages.map((m, i) => (
                  <p key={i} className={`timeline__msg timeline__msg--${m.status}`}>
                    {m.message}
                  </p>
                ))}
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
