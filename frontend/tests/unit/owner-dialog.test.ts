/**
 * The verification dialog's first view, rendered on the server. Run with `npm run test:unit:dialog` (node:test through tsx, borrowed from backend,
 * because Playwright's own JSX transform turns components into test descriptors that React cannot render).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { OwnerVerificationDialog } from '../../shared/owner/OwnerVerificationDialog';

const noop = () => undefined;
const dialog = (props: Record<string, unknown>) =>
  renderToStaticMarkup(
    React.createElement(OwnerVerificationDialog as unknown as React.ComponentType<Record<string, unknown>>, { target: null, warning: '', onTicket: noop, onCancel: noop, ...props }),
  );

const html = dialog({ operation: 'keys.rotate', label: 'Rotate the signing key', warning: 'Every service will fetch the new key.' });

test('is an accessible dialog with the action, the warning and the plain explanation', () => {
  for (const s of ['role="dialog"', 'aria-modal="true"', 'aria-labelledby=', 'You are about to', 'rotate the signing key', 'Every service will fetch the new key.', 'This needs your owner authorisation', 'aria-live="assertive"']) {
    assert.ok(html.includes(s), `missing: ${s}`);
  }
});

test('the first screen does not claim an authenticator step before the server has said whether there is one', () => {
  const text = html.replace(/<[^>]+>/g, ' ');
  assert.ok(text.includes('If your owner verification also uses an authenticator app'));
  assert.ok(!text.includes('type a code from your authenticator app.'));
});

test('offers Cancel and Continue, and uses no protocol words', () => {
  assert.ok(html.includes('>Cancel<'));
  assert.ok(html.includes('>Continue<'));
  assert.doesNotMatch(html.replace(/<[^>]+>/g, ' '), /\b(JWT|TOTP|jti|ticket)\b/i);
});

test('shows the not-enrolled explanation instead of steps, with only a Close button', () => {
  const out = dialog({ operation: 'x', label: 'L', notEnrolled: true });
  assert.ok(out.includes('has not been set up yet'));
  assert.ok(out.includes('npm run owner:enroll'));
  assert.ok(out.includes('>Close<'));
  assert.ok(!out.includes('>Continue<'));
});

test('asks what the authorisation is for when the action names a target', () => {
  assert.ok(dialog({ operation: 'dms.tenant.create', label: 'Create a tenant', needsTarget: true }).includes('What is this authorisation for?'));
});
