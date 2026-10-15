'use client';

import { useState } from 'react';
import toast from 'react-hot-toast';
import { Copy, Download, Printer } from 'lucide-react';

/**
 * The one moment the recovery codes are shown. They are not stored anywhere readable, so the person is asked to keep them (copy,
 * download or print) and to confirm they have before this goes away; the confirm button stays off until they say so.
 */
export function RecoveryCodes({ codes, email, onDone }: { codes: string[]; email: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const text = `Recovery codes for ${email}\nEach code works once. Keep them somewhere safe and private.\n\n${codes.join('\n')}\n`;

  function download() {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section aria-labelledby="recovery-title" className="sso-recovery">
      <h3 id="recovery-title" style={{ margin: '0 0 4px', fontSize: 16 }}>Save your recovery codes</h3>
      <p className="sub" style={{ marginBottom: 12 }}>
        If you lose your phone, each of these codes lets you sign in once. They are shown <strong>only now</strong>. Keep them somewhere safe, apart from your phone.
      </p>
      <ul className="sso-recovery-grid" aria-label="Recovery codes">
        {codes.map((c) => <li key={c}><code>{c}</code></li>)}
      </ul>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '12px 0' }}>
        <button type="button" className="ui-btn ui-btn-secondary ui-btn-sm" onClick={() => navigator.clipboard.writeText(codes.join('\n')).then(() => toast.success('Copied'), () => toast.error('Could not copy'))}>
          <Copy aria-hidden="true" /> Copy
        </button>
        <button type="button" className="ui-btn ui-btn-secondary ui-btn-sm" onClick={download}>
          <Download aria-hidden="true" /> Download
        </button>
        <button type="button" className="ui-btn ui-btn-secondary ui-btn-sm" onClick={() => window.print()}>
          <Printer aria-hidden="true" /> Print
        </button>
      </div>
      <label className="ui-switch">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span className="track" aria-hidden="true" />
        <span>I have saved these codes</span>
      </label>
      <button type="button" className="sso-button" disabled={!saved} onClick={onDone}>Continue</button>
    </section>
  );
}
