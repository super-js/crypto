module.exports = {
    root: true,
    parser: '@typescript-eslint/parser',
    plugins: [
      '@typescript-eslint',
    ],
    extends: [
      'eslint:recommended',
      'plugin:@typescript-eslint/recommended',
    ],
    rules: {
        "no-empty-pattern": ["warn"],
        "@typescript-eslint/ban-types": ["warn"],
        "semi": ["error", "always"],
        "no-prototype-builtins": ["warn"],
        "prefer-const": ["warn"],
        "no-useless-escape": ["warn"]
      }
  };
  