'use client';

import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

type PwaInstallState = {
  canInstall: boolean;
  isIos: boolean;
  isInstalled: boolean;
  promptInstall: () => Promise<void>;
};

const PwaInstallContext = createContext<PwaInstallState | null>(null);

/**
 * Captures the browser's one-shot beforeinstallprompt event at app startup.
 * This must live above route-level loading states: mounting the listener only
 * when the portal finishes fetching its data can miss the event permanently
 * for that page load, leaving the install button hidden in Chromium.
 */
export function PwaInstallProvider({ children }: { children: ReactNode }) {
  const [deferredEvent, setDeferredEvent] = useState<BeforeInstallPromptEvent | null>(null);
  const [isInstalled, setIsInstalled] = useState(false);
  const [isIos, setIsIos] = useState(false);

  useEffect(() => {
    const standalone =
      window.matchMedia('(display-mode: standalone)').matches ||
      (window.navigator as unknown as { standalone?: boolean }).standalone === true;
    setIsInstalled(standalone);

    const ua = window.navigator.userAgent;
    const isIosDevice = /iPad|iPhone|iPod/.test(ua);
    setIsIos(isIosDevice && !(window.navigator as unknown as { standalone?: boolean }).standalone);

    const onBeforeInstallPrompt = (event: Event) => {
      event.preventDefault();
      setDeferredEvent(event as BeforeInstallPromptEvent);
    };
    const onAppInstalled = () => {
      setDeferredEvent(null);
      setIsInstalled(true);
    };

    window.addEventListener('beforeinstallprompt', onBeforeInstallPrompt);
    window.addEventListener('appinstalled', onAppInstalled);
    return () => {
      window.removeEventListener('beforeinstallprompt', onBeforeInstallPrompt);
      window.removeEventListener('appinstalled', onAppInstalled);
    };
  }, []);

  const promptInstall = useCallback(async () => {
    if (!deferredEvent) return;
    await deferredEvent.prompt();
    const choice = await deferredEvent.userChoice;
    if (choice.outcome === 'accepted') setDeferredEvent(null);
  }, [deferredEvent]);

  const value = useMemo<PwaInstallState>(
    () => ({
      canInstall: !!deferredEvent && !isInstalled,
      isIos,
      isInstalled,
      promptInstall,
    }),
    [deferredEvent, isInstalled, isIos, promptInstall],
  );

  return createElement(PwaInstallContext.Provider, { value }, children);
}

export function usePwaInstall() {
  const context = useContext(PwaInstallContext);
  if (!context) {
    throw new Error('usePwaInstall must be used within PwaInstallProvider');
  }
  return context;
}
