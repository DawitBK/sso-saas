'use client';

import { useEffect, useState } from 'react';
import QRCode from 'qrcode';

/**
 * A QR code drawn in the browser. The text (an otpauth:// address holding the person's new two-factor secret) never leaves the page:
 * there is no image service involved, which is the whole reason this is generated here rather than linked from one.
 */
export function QrCode({ text, size = 176, label }: { text: string; size?: number; label: string }) {
  const [src, setSrc] = useState<string | null>(null);
  useEffect(() => {
    let current = true;
    QRCode.toDataURL(text, { width: size, margin: 1, errorCorrectionLevel: 'M' })
      .then((url) => { if (current) setSrc(url); })
      .catch(() => { if (current) setSrc(null); });
    return () => { current = false; };
  }, [text, size]);
  if (!src) return <div className="ui-skeleton" style={{ width: size, height: size }} aria-hidden="true" />;
  // eslint-disable-next-line @next/next/no-img-element -- a data: URL, nothing for next/image to optimise
  return <img src={src} width={size} height={size} alt={label} style={{ background: '#fff', borderRadius: 8, padding: 4 }} />;
}
