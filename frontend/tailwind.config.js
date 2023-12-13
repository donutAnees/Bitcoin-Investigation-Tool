/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      backgroundImage:{
        'dark-bg' : "url('/public/images/heroglowdark.jpg')",
        'light-bg' : "url('/public/images/heroglow.jpg')",
        'icon-dark-bg' : "url('/public/images/titlecard.png')",
        'icon-bg' : "url('/public/images/titlecardlight.png')",
        'purple-bg' :"url('/public/images/wallet-hero-gradient.jpg')",

      },
      dropShadow: {
        '3xl': '0px 0px 35px rgba(255, 255, 255, 0.5)',
      },
      colors:{
        'bluish-black': '#05070e',
        'brightRed': '#FF0000',
      } , 
      animation: {
        'slide-in': 'slide-in 1.25s',
        'wiggle': 'wiggle 1s ease-in-out infinite',
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
        wiggle: {
          '0%, 100%': { transform: 'rotate(-3deg)' },
          '50%': { transform: 'rotate(3deg)' },
        },
      },
    }, 
  },
  plugins: [],
  
}

