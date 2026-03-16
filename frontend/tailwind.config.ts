import type { Config } from 'tailwindcss'

const config: Config = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Brand accent — "Argus eye" cyan-sky
        accent: {
          DEFAULT: '#0ea5e9',  // sky-500
          hover:   '#0284c7',  // sky-600
          subtle:  '#0c4a6e',  // sky-950 (for dark bg badges)
        },
        // Status
        online:  '#22c55e',   // green-500
        offline: '#ef4444',   // red-500
        unknown: '#a1a1aa',   // zinc-400
        // Dark sidebar
        sidebar: {
          DEFAULT: '#18181b',  // zinc-900
          hover:   '#27272a',  // zinc-800
          active:  '#3f3f46',  // zinc-700
          border:  '#27272a',  // zinc-800
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.2s ease-in-out',
        'slide-in': 'slideIn 0.2s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-8px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
export default config
