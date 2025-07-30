/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: 'var(--background)',
        card: 'var(--card-bg)',
        primary: 'var(--text-primary)',
        secondary: 'var(--text-secondary)'
      }
    },
  },
  plugins: [],
}