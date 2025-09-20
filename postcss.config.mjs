/** @type {import('postcss-load-config').Config} */
export default {
  plugins: {
    'postcss-import': {},
    'postcss-nesting': {},
    'tailwindcss/nesting': 'postcss-nesting',
    tailwindcss: {},
    autoprefixer: {},
  },
};
