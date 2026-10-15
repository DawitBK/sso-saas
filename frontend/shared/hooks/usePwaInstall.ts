'use client';

import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from 'react';

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
/** True while the page is running as an installed app rather than in a tab. */
function subscribeDisplayMode(onChange: () => void) {
  const mql = window.matchMedia('(display-mode: standalone)');
  mql.addEventListener('change', onChange);
  return () => mql.removeEventListener('change', onChange);
}
function getStandaloneSnapshot() {
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    (window.navigator as unknown as { standalone?: boolean }).standalone === true
  );
}
function getIosSnapshot() {
  const nav = window.navigator as unknown as { standalone?: boolean };
  return /iPad|iPhone|iPod/.test(window.navigator.userAgent) && !nav.standalone;
}
/** `useSyncExternalStore` subscribe for a value that never changes after mount. */
const SUBSCRIBE_NEVER = () => () => {};
const FALSE_ON_SERVER = () => false;

export function PwaInstallProvider({ children }: { children: ReactNode }) {
  const [deferredEvent, setDeferredEvent] = useState<BeforeInstallPromptEvent | null>(null);
  // Set only by the `appinstalled` event. Installing does not always flip
  // display-mode in the current tab, so this is OR-ed with the media query
  // below rather than replacing it.
  const [sawInstallEvent, setSawInstallEvent] = useState(false);

  // Both of these are browser state read through useSyncExternalStore instead
  // of an effect that setStates them in. That is React's supported way to read
  // an external source that has no value during SSR, and it is strictly more
  // correct here: display-mode is a live media query, so leaving a standalone
  // window now updates `isInstalled` instead of leaving it stuck at its mount
  // value. The effect it replaces set state synchronously in its body, which
  // react-hooks/set-state-in-effect rejects under eslint-config-next 16.
  const standalone = useSyncExternalStore(subscribeDisplayMode, getStandaloneSnapshot, FALSE_ON_SERVER);
  const isIos = useSyncExternalStore(SUBSCRIBE_NEVER, getIosSnapshot, FALSE_ON_SERVER);
  const isInstalled = standalone || sawInstallEvent;

  useEffect(() => {
    const onBeforeInstallPrompt = (event: Event) => {
      event.preventDefault();
      setDeferredEvent(event as BeforeInstallPromptEvent);
    };
    const onAppInstalled = () => {
      setDeferredEvent(null);
      setSawInstallEvent(true);
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
