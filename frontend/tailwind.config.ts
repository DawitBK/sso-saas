import type { Config } from 'tailwindcss';

export default {
  darkMode: 'class',
  content: [
    './app/**/*.{ts,tsx}',
    './features/**/*.{ts,tsx}',
    './providers/**/*.{ts,tsx}',
    './shared/**/*.{ts,tsx}',
    './state/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'sans-serif',
        ],
      },
      colors: {
        brand: {
          DEFAULT: 'var(--brand)',
          2: 'var(--brand-2)',
          ink: 'var(--brand-ink)',
        },
        bg: 'var(--bg)',
        card: 'var(--card)',
        ink: 'var(--ink)',
        muted: 'var(--muted)',
        border: 'var(--border)',
        'input-bg': 'var(--input-bg)',
        'input-ink': 'var(--input-ink)',
        danger: {
          DEFAULT: 'var(--danger)',
          bg: 'var(--danger-bg)',
          border: 'var(--danger-border)',
        },
        sidebar: {
          bg: 'var(--sidebar-bg)',
          border: 'var(--sidebar-border)',
          text: 'var(--sidebar-text)',
          'text-hover': 'var(--sidebar-text-hover)',
          'text-active': 'var(--sidebar-text-active)',
          'active-bg': 'var(--sidebar-active-bg)',
          'active-border': 'var(--sidebar-active-border)',
          'hover-bg': 'var(--sidebar-hover-bg)',
          'section-text': 'var(--sidebar-section-text)',
          'logo-text': 'var(--sidebar-logo-text)',
          'logo-sub': 'var(--sidebar-logo-sub)',
        },
      },
      boxShadow: {
        card: '0 20px 60px var(--shadow)',
      },
    },
  },
  plugins: [],
} satisfies Config;
