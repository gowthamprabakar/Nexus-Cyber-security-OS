// Minimal placeholder — Task 5 replaces this with the real detail drawer.
// The role="dialog" wrapper (and the mock's drawer styles) live on ListPage.
export function DetailPanel({
  row,
  onClose,
}: {
  row: Record<string, unknown>;
  onClose: () => void;
}) {
  return (
    <div style={{ padding: '18px 20px' }}>
      <button
        onClick={onClose}
        aria-label="Close"
        style={{
          height: 28,
          padding: '0 12px',
          borderRadius: 7,
          border: '1px solid var(--border2)',
          background: 'transparent',
          color: 'var(--text2)',
          fontFamily: 'inherit',
          fontSize: 12.5,
          cursor: 'pointer',
        }}
      >
        Close
      </button>
      <div style={{ marginTop: 14, fontSize: 14, fontWeight: 600 }}>{String(row.cve ?? '')}</div>
    </div>
  );
}
