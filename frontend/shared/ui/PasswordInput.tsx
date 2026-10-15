'use client';

import { useId, useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';

/**
 * A password field with a show/hide control and a Caps Lock warning. Both exist because they prevent the two commonest reasons
 * for a failed sign-in (a mistyped password nobody could check, and Caps Lock) without weakening anything: the value is still a
 * password input until the person asks to see it, and the browser's password manager still recognises it (give it the right
 * `autoComplete`: "current-password" to sign in, "new-password" when choosing one).
 */
export function PasswordInput({
  value,
  onChange,
  autoComplete,
  id,
  placeholder,
  minLength,
  required = true,
  autoFocus,
  describedBy,
  className = 'sso-input',
}: {
  value: string;
  onChange: (v: string) => void;
  autoComplete: 'current-password' | 'new-password';
  id?: string;
  placeholder?: string;
  minLength?: number;
  required?: boolean;
  autoFocus?: boolean;
  describedBy?: string;
  className?: string;
}) {
  const generated = useId();
  const inputId = id ?? generated;
  const [shown, setShown] = useState(false);
  const [caps, setCaps] = useState(false);
  return (
    <div className="sso-password">
      <div className="sso-password-wrap">
        <input
          id={inputId}
          name={autoComplete === 'new-password' ? 'new-password' : 'password'}
          type={shown ? 'text' : 'password'}
          className={className}
          required={required}
          minLength={minLength}
          autoFocus={autoFocus}
          autoComplete={autoComplete}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          placeholder={placeholder}
          value={value}
          aria-describedby={describedBy}
          onChange={(e) => onChange(e.target.value)}
          onKeyUp={(e) => setCaps(e.getModifierState('CapsLock'))}
          onKeyDown={(e) => setCaps(e.getModifierState('CapsLock'))}
          onBlur={() => setCaps(false)}
        />
        <button type="button" className="sso-password-toggle" onClick={() => setShown((s) => !s)} aria-pressed={shown} aria-label={shown ? 'Hide password' : 'Show password'} title={shown ? 'Hide password' : 'Show password'}>
          {shown ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
        </button>
      </div>
      {caps ? <p className="sso-caps" role="status">Caps Lock is on.</p> : null}
    </div>
  );
}
