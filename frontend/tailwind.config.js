/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Tactical blue palette — precision instrument, not cyberpunk
        signal: {
          50:  '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',  // primary interactive
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
        },
        // Surface hierarchy
        void:  '#070b13',   // page background
        base:  '#0c1220',   // sidebar
        raise: '#111827',   // elevated panels
        lift:  '#19243a',   // cards
        wire:  'rgba(96,130,182,0.14)',  // borders
        // Semantic
        heat:  '#f43f5e',
        amber: '#f59e0b',
        go:    '#22c55e',
        ice:   '#67e8f9',
        // Severity
        severity: {
          critical: '#f43f5e',
          high:     '#f97316',
          medium:   '#f59e0b',
          low:      '#67e8f9',
          info:     '#64748b',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', { lineHeight: '1.4', letterSpacing: '0.06em' }],
      },
      borderRadius: {
        sm: '3px',
        DEFAULT: '4px',
        md: '6px',
        lg: '8px',
        xl: '12px',
      },
      boxShadow: {
        signal: '0 0 0 1px rgba(37,99,235,0.6), 0 0 16px rgba(37,99,235,0.2)',
        heat:   '0 0 12px rgba(244,63,94,0.3)',
        go:     '0 0 10px rgba(34,197,94,0.25)',
        panel:  '0 4px 24px rgba(0,0,0,0.5)',
      },
      animation: {
        'ping-slow':  'ping 2.5s cubic-bezier(0,0,0.2,1) infinite',
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'fade-in':    'fadeIn 0.18s ease-out',
        'slide-up':   'slideUp 0.22s ease-out',
      },
      keyframes: {
        fadeIn:  { from: { opacity: '0' },                              to: { opacity: '1' } },
        slideUp: { from: { opacity: '0', transform: 'translateY(6px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
      },
    },
  },
  plugins: [],
}
