/**
 * Convenience aliases over the generated OpenAPI types.
 * Source of truth: ../../contracts/openapi.json → src/api/schema.d.ts (npm run gen:api).
 */
import type { components } from './schema';

type S = components['schemas'];

export type AuditReport = S['AuditReport'];
export type ContractInfo = S['ContractInfo'];
export type DetectorSource = S['DetectorSource'];
export type EVMVerdict = S['EVMVerdict'];
export type ErrorResponse = S['ErrorResponse'];
export type Evidence = S['Evidence'];
export type Finding = S['Finding'];
export type FindingsResponse = S['FindingsResponse'];
export type Health = S['Health'];
export type Job = S['Job'];
export type JobStage = S['JobStage'];
export type JobStatus = S['JobStatus'];
export type LLMVerdict = S['LLMVerdict'];
export type LineRange = S['LineRange'];
export type RegistryEntry = S['RegistryEntry'];
export type Severity = S['Severity'];
export type SeverityCounts = S['SeverityCounts'];
export type StageEvent = S['StageEvent'];
export type SubmitResponse = S['SubmitResponse'];
export type Verification = S['Verification'];
export type VerifyRequest = S['VerifyRequest'];
export type VerifyResponse = S['VerifyResponse'];
export type VulnClass = S['VulnClass'];

/** Ordered as in the contract enum (pipeline order). */
export const JOB_STAGES: readonly JobStage[] = [
  'received',
  'parsing',
  'static_analysis',
  'ml_inference',
  'evidence',
  'llm_verification',
  'evm_validation',
  'reporting',
  'done',
];

/** Most severe first. */
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const VULN_CLASSES: readonly VulnClass[] = [
  'reentrancy',
  'unchecked_call',
  'tx_origin',
  'timestamp_dependence',
  'integer_overflow',
  'access_control',
  'delegatecall',
  'unprotected_selfdestruct',
  'denial_of_service',
  'bad_randomness',
  'other',
];
