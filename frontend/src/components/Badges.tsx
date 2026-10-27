import type { DetectorSource, EVMVerdict, LLMVerdict, Severity } from '../api/types';
import { humanize } from '../lib/format';

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge sev sev--${severity}`} data-severity={severity}>
      {severity.toUpperCase()}
    </span>
  );
}

const DETECTOR_LABEL: Record<DetectorSource, string> = {
  slither: 'Slither',
  heuristic: 'Heuristic',
  gnn: 'GNN',
  baseline_ml: 'Baseline ML',
  llm: 'LLM',
  mock: 'MOCK',
};

export function DetectorBadge({ detector }: { detector: DetectorSource }) {
  return (
    <span className={`badge det det--${detector}`} title={`Detected by ${DETECTOR_LABEL[detector]}`}>
      {DETECTOR_LABEL[detector]}
    </span>
  );
}

type Tone = 'good' | 'bad' | 'warn' | 'neutral' | 'error';

const LLM_META: Record<LLMVerdict, { label: string; tone: Tone; help: string }> = {
  not_run: { label: 'Not run', tone: 'neutral', help: 'LLM verification was not run (e.g. no LLM key configured).' },
  supported: { label: 'Supported', tone: 'good', help: 'The LLM reviewer found the evidence supports this finding.' },
  refuted: { label: 'Refuted', tone: 'bad', help: 'The LLM reviewer judged this finding a likely false positive.' },
  uncertain: { label: 'Uncertain', tone: 'warn', help: 'The LLM reviewer could not decide.' },
  error: { label: 'Error', tone: 'error', help: 'LLM verification failed to run.' },
};

const EVM_META: Record<EVMVerdict, { label: string; tone: Tone; help: string }> = {
  not_run: { label: 'Not run', tone: 'neutral', help: 'EVM validation was not run.' },
  confirmed: { label: 'Confirmed', tone: 'bad', help: 'The exploit was reproduced on a local EVM (anvil).' },
  not_reproduced: { label: 'Not reproduced', tone: 'warn', help: 'The exploit could not be reproduced on a local EVM.' },
  not_applicable: { label: 'N/A', tone: 'neutral', help: 'EVM validation does not apply to this vulnerability class.' },
  error: { label: 'Error', tone: 'error', help: 'EVM validation failed to run.' },
};

export function VerificationBadge(props: { kind: 'llm'; status: LLMVerdict } | { kind: 'evm'; status: EVMVerdict }) {
  const meta = props.kind === 'llm' ? LLM_META[props.status] : EVM_META[props.status];
  const prefix = props.kind === 'llm' ? 'LLM' : 'EVM';
  return (
    <span
      className={`badge verif verif--${meta.tone}`}
      data-testid={`verif-${props.kind}`}
      data-status={props.status}
      title={meta.help}
      aria-label={`${prefix} verification: ${meta.label}. ${meta.help}`}
    >
      <span className="verif__kind">{prefix}</span> {meta.label}
    </span>
  );
}

export function VulnClassTag({ value }: { value: string }) {
  return <span className="tag">{humanize(value)}</span>;
}
