export interface ApiConfig {
  baseUrl: string;
  apiKey?: string;
}

export const DEFAULT_API_BASE = 'http://localhost:8000';

export function readApiConfig(env: Record<string, string | boolean | undefined> = import.meta.env): ApiConfig {
  const rawBase = typeof env.VITE_API_BASE === 'string' && env.VITE_API_BASE.trim() !== '' ? env.VITE_API_BASE.trim() : DEFAULT_API_BASE;
  const apiKey = typeof env.VITE_API_KEY === 'string' && env.VITE_API_KEY.trim() !== '' ? env.VITE_API_KEY.trim() : undefined;
  return { baseUrl: rawBase.replace(/\/+$/, ''), apiKey };
}

export function mocksEnabled(env: Record<string, string | boolean | undefined> = import.meta.env): boolean {
  return env.VITE_USE_MOCKS === 'true' || env.VITE_USE_MOCKS === true;
}
