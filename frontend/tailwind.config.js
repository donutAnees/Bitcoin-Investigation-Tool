/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      backgroundImage:{
        'dark-bg' : "url('/public/images/heroglowdark.jpg')",
        'light-bg' : "url('/public/images/heroglow.jpg')",
      },
      colors:{
        'bluish-black': '#0F172A',
      } , 
      animation: {
        'slide-in': 'slide-in 1.25s',
      },
      keyframes: {
        'slide-in': {
          '0%': {
            transform: 'translateX(-25%)',
          },
          '100%': {
            transform: 'translateX(0)',
          },
        },
      },
    }, 
  },
  plugins: [],
}

