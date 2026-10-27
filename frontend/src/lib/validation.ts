/** Client-side limit; the backend enforces its own limit too (413). */
export const MAX_UPLOAD_BYTES = 512 * 1024;

export type FileValidation = { ok: true } | { ok: false; reason: string };

export function validateSolidityFile(file: File): FileValidation {
  if (!/\.sol$/i.test(file.name)) {
    return { ok: false, reason: `"${file.name}" is not a Solidity file. Only .sol files are accepted.` };
  }
  if (file.size === 0) return { ok: false, reason: `"${file.name}" is empty.` };
  if (file.size > MAX_UPLOAD_BYTES) {
    return {
      ok: false,
      reason: `"${file.name}" is ${(file.size / 1024).toFixed(1)} KiB; the limit is 512 KiB.`,
    };
  }
  return { ok: true };
}

export async function readFileText(file: Blob): Promise<string> {
  if (typeof file.text === 'function') return file.text();
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result ?? ''));
    r.onerror = () => reject(r.error ?? new Error('Could not read file'));
    r.readAsText(file);
  });
}
