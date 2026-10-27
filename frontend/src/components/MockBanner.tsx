export function MockBanner({ reason }: { reason?: string }) {
  return (
    <div className="mock-banner" role="alert" data-testid="mock-banner">
      <strong>MOCK DATA — not a real analysis.</strong>
      <span>{reason ?? 'Results shown are synthetic placeholders and must not be used as security findings.'}</span>
    </div>
  );
}
