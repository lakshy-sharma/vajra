/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  // Honour the OS preference; the root <html> also accepts a manual
  // data-theme="dark"|"light" attribute for the in-app toggle.
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        // Semantic palette — same names in dark and light; only values change.
        surface:  { DEFAULT: 'rgb(var(--surface) / <alpha-value>)' },
        'surface-2': { DEFAULT: 'rgb(var(--surface-2) / <alpha-value>)' },
        border:   { DEFAULT: 'rgb(var(--border) / <alpha-value>)' },
        muted:    { DEFAULT: 'rgb(var(--muted) / <alpha-value>)' },
        // Severity colours are consistent across themes.
        critical: '#ef4444',
        high:     '#f97316',
        medium:   '#eab308',
        low:      '#3b82f6',
        clean:    '#22c55e',
      },
    },
  },
  plugins: [],
}
