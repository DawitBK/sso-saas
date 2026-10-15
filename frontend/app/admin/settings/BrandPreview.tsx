'use client';

/** The sign-in card as it will look with the branding values being edited (saved or not), in the light and the dark theme side by side. */
const HEX = /^#[0-9a-f]{6}$/i;

function ink(hex: string): string {
  const n = parseInt(hex.slice(1), 16);
  const ch = (v: number) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; };
  const lum = 0.2126 * ch((n >> 16) & 255) + 0.7152 * ch((n >> 8) & 255) + 0.0722 * ch(n & 255);
  // Black text on the accent wins when its contrast is higher than white's: (lum+.05)/.05 vs 1.05/(lum+.05).
  return (lum + 0.05) / 0.05 > 1.05 / (lum + 0.05) ? '#000000' : '#ffffff';
}

function Card({ dark, p }: { dark: boolean; p: Props }) {
  const accentRaw = dark ? p.accentDark : p.accent;
  const accent = HEX.test(accentRaw) ? accentRaw : '#888888';
  const page = dark ? '#0b1220' : '#f8fafc';
  const card = dark ? '#111a2e' : '#ffffff';
  const text = dark ? '#e2e8f0' : '#0f172a';
  const muted = dark ? '#94a3b8' : '#64748b';
  return (
    <div className="brand-preview" style={{ background: page, color: text }} aria-label={dark ? 'Dark theme preview' : 'Light theme preview'}>
      <div className="brand-preview-card" style={{ background: card, borderColor: dark ? '#1e293b' : '#e2e8f0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: accent, color: ink(accent), display: 'grid', placeItems: 'center', fontWeight: 800 }} aria-hidden="true">
            {(p.productName.trim()[0] ?? 'K').toUpperCase()}
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 15 }}>{p.productName || 'Product name'}</div>
            <div style={{ fontSize: 12, color: muted }}>{p.tagline}</div>
          </div>
        </div>
        {p.notice ? <div className="brand-preview-notice">{p.notice}</div> : null}
        <div style={{ marginTop: 14, fontSize: 12, fontWeight: 600, color: muted }}>Email</div>
        <div style={{ height: 32, borderRadius: 8, border: `1px solid ${dark ? '#1e293b' : '#e2e8f0'}`, marginTop: 4 }} />
        <div className="pv-btn" style={{ background: accent, color: ink(accent) }}>Continue</div>
        {p.support ? <div style={{ marginTop: 12, fontSize: 12, color: muted }}>Need help? {p.support}</div> : null}
        <div style={{ marginTop: 12, fontSize: 11, color: muted, textAlign: 'center' }}>{p.footer}</div>
      </div>
    </div>
  );
}

interface Props {
  productName: string;
  tagline: string;
  accent: string;
  accentDark: string;
  notice: string;
  support: string;
  footer: string;
}

export function BrandPreview(p: Props) {
  return (
    <div className="admin-card">
      <h2 className="admin-section-title" style={{ marginTop: 0 }}>Preview</h2>
      <p className="admin-hint" style={{ marginTop: 0 }}>How the sign-in page will look with the values above, including ones you have not saved yet.</p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 14, marginTop: 12 }}>
        <Card dark={false} p={p} />
        <Card dark p={p} />
      </div>
    </div>
  );
}
