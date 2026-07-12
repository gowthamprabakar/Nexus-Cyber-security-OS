export function GapState({ title, needs }: { title: string; needs: string }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: 320,
        padding: '40px 24px',
      }}
    >
      <div
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 12,
          padding: '36px 40px',
          maxWidth: 480,
          width: '100%',
          textAlign: 'center',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            marginBottom: 16,
            color: 'var(--text3)',
          }}
        >
          <svg
            width="32"
            height="32"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--accent)"
            strokeWidth={1.6}
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="9"></circle>
            <path d="M12 16v-4M12 8h.01"></path>
          </svg>
        </div>
        <h2
          style={{
            fontSize: 21,
            fontWeight: 600,
            letterSpacing: '-0.02em',
            margin: '0 0 10px',
            color: 'var(--text)',
          }}
        >
          {title}
        </h2>
        <p style={{ fontSize: 13, lineHeight: 1.6, color: 'var(--text3)', margin: 0 }}>
          Not available yet — needs {needs}. This will turn real when that backend lands.
        </p>
      </div>
    </div>
  );
}
