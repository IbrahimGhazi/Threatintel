/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // TI Platform Design System – all values use CSS variables for theme switching.
        // Variables are defined in globals.css under :root (light) and .dark (dark).
        bg: {
          base:     "rgb(var(--bg-base) / <alpha-value>)",
          surface:  "rgb(var(--bg-surface) / <alpha-value>)",
          elevated: "rgb(var(--bg-elevated) / <alpha-value>)",
          overlay:  "rgb(var(--bg-overlay) / <alpha-value>)",
        },
        border: {
          DEFAULT: "rgb(var(--border-default) / <alpha-value>)",
          subtle:  "rgb(var(--border-subtle) / <alpha-value>)",
          strong:  "rgb(var(--border-strong) / <alpha-value>)",
        },
        text: {
          primary:   "rgb(var(--text-primary) / <alpha-value>)",
          secondary: "rgb(var(--text-secondary) / <alpha-value>)",
          muted:     "rgb(var(--text-muted) / <alpha-value>)",
          inverse:   "rgb(var(--text-inverse) / <alpha-value>)",
        },
        accent: {
          DEFAULT:  "rgb(var(--accent) / <alpha-value>)",
          dim:      "rgb(var(--accent-dim) / <alpha-value>)",
          subtle:   "rgb(var(--accent) / 0.12)",
          blue:     "rgb(var(--accent-blue) / <alpha-value>)",
          blue_dim: "rgb(var(--accent-blue-dim) / <alpha-value>)",
        },
        severity: {
          critical: "#f04060",
          high:     "#f07030",
          medium:   "#f0a830",
          low:      "#50a0f0",
          info:     "#60809a",
        },
        status: {
          success:  "#30c060",
          warning:  "#f0a830",
          error:    "#f04060",
          running:  "#4f8ef7",
        },
      },
      fontFamily: {
        mono:  ["'JetBrains Mono'", "'Fira Code'", "Consolas", "monospace"],
        sans:  ["'Inter'", "system-ui", "sans-serif"],
      },
      fontSize: {
        "2xs": ["0.65rem", { lineHeight: "1rem" }],
      },
      boxShadow: {
        card:   "0 1px 3px rgba(0,0,0,0.12), 0 0 0 1px rgb(var(--border-default) / 0.8)",
        glow:   "0 0 12px rgba(0,196,204,0.25)",
        "glow-red": "0 0 12px rgba(240,64,96,0.25)",
      },
      backgroundImage: {
        "grid-pattern": "linear-gradient(rgb(var(--border-default) / 0.3) 1px, transparent 1px), linear-gradient(90deg, rgb(var(--border-default) / 0.3) 1px, transparent 1px)",
      },
      backgroundSize: {
        "grid": "40px 40px",
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "fade-in":    "fadeIn 0.2s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%":   { opacity: 0, transform: "translateY(4px)" },
          "100%": { opacity: 1, transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};
