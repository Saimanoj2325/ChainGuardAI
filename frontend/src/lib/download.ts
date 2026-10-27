export function downloadText(filename: string, text: string, mime: string): void {
  if (typeof URL.createObjectURL !== 'function') return; // non-browser env (tests)
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
