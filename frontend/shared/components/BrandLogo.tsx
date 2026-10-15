'use client';

import { useBranding } from '../branding/BrandingProvider';

/** The product mark on the sign-in pages: the first letter of the product name on the accent colour, then the name and tagline. */
export function BrandLogo() {
  const { productName, tagline } = useBranding();
  return (
    <div className="sso-brand">
      <div className="sso-brand-dot" aria-hidden="true">{(productName.trim()[0] ?? 'K').toUpperCase()}</div>
      <div>
        <h1>{productName}</h1>
        {tagline ? <p>{tagline}</p> : null}
      </div>
    </div>
  );
}
