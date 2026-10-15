import { useSyncExternalStore } from 'react';

const subscribe = () => () => {};

/**
 * False while the page is server-rendered and during hydration, true once React is running in the browser.
 *
 * A form is only wired to its handler after hydration. Before that, pressing Enter makes the browser submit it natively,
 * which for a form with no method is a GET carrying every field in the address bar: a password in the URL, the history and
 * every proxy log. The sign-in forms therefore declare method="post" and expose this flag (`data-hydrated`) so that automated
 * tests, and anything else that drives the page, can wait until typing into it is safe (React resets a controlled input that
 * was filled before it took over).
 */
export function useHydrated(): boolean {
  return useSyncExternalStore(subscribe, () => true, () => false);
}
