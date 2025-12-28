/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Gemini-inspired dark theme
        'cyber-bg': '#1e1f20',
        'cyber-surface': '#282a2c',
        'cyber-card': '#303134',
        'cyber-border': '#3c4043',
        'cyber-accent': '#8ab4f8',
        'cyber-accent-dim': '#669df6',
        'cyber-success': '#81c995',
        'cyber-warning': '#fdd663',
        'cyber-error': '#f28b82',
        'cyber-text': '#e3e3e3',
        'cyber-text-dim': '#9aa0a6',
        // Gradient colors
        'gemini-blue': '#8ab4f8',
        'gemini-purple': '#c58af9',
        'gemini-pink': '#f28b82',
        // Swarm colors
        'swarm-red': '#f28b82',
        'swarm-blue': '#8ab4f8',
        'swarm-judge': '#c58af9',
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        'sans': ['Google Sans', 'Segoe UI', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan': 'scan 2s ease-in-out infinite',
        'gradient-shift': 'gradientShift 3s ease infinite',
        'shimmer': 'shimmer 2s ease-in-out infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(138, 180, 248, 0.3)' },
          '100%': { boxShadow: '0 0 25px rgba(138, 180, 248, 0.6)' },
        },
        scan: {
          '0%, 100%': { opacity: 0.3 },
          '50%': { opacity: 1 },
        },
        gradientShift: {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
        shimmer: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'gemini-gradient': 'linear-gradient(135deg, #8ab4f8 0%, #c58af9 50%, #f28b82 100%)',
      },
      boxShadow: {
        'glow-blue': '0 0 20px rgba(138, 180, 248, 0.4)',
        'glow-purple': '0 0 20px rgba(197, 138, 249, 0.4)',
      },
    },
  },
  plugins: [],
}
