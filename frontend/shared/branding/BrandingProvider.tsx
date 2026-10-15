'use client';

import { createContext, useContext } from 'react';
import { DEFAULT_BRANDING, type Branding } from './branding';

const BrandingContext = createContext<Branding>(DEFAULT_BRANDING);

export function BrandingProvider({ value, children }: { value: Branding; children: React.ReactNode }) {
  return <BrandingContext.Provider value={value}>{children}</BrandingContext.Provider>;
}

/** The branding the root layout fetched for this page view. */
export function useBranding(): Branding {
  return useContext(BrandingContext);
}
