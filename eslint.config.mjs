import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import { dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const eslintConfig = [
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    plugins: {
      security,
      "no-unsanitized": noUnsanitized,
    },
    rules: {
      // ===== TypeScript strictness =====
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "@typescript-eslint/no-non-null-assertion": "warn",
      "@typescript-eslint/ban-ts-comment": "warn",
      "@typescript-eslint/prefer-as-const": "off",
      "@typescript-eslint/no-unused-disable-directive": "warn",
      "@typescript-eslint/consistent-type-imports": "off",

      // ===== React rules =====
      "react-hooks/exhaustive-deps": "warn",
      "react-hooks/purity": "off",
      "react/no-unescaped-entities": "off",
      "react/display-name": "off",
      "react/prop-types": "off",
      "react-compiler/react-compiler": "off",

      // ===== Next.js rules =====
      "@next/next/no-img-element": "off",
      "@next/next/no-html-link-for-pages": "off",

      // ===== General JavaScript rules =====
      "prefer-const": "warn",
      "no-unused-vars": "off",
      "no-console": ["warn", { allow: ["error"] }],
      "no-debugger": "error",
      "no-empty": "warn",
      "no-irregular-whitespace": "warn",
      "no-case-declarations": "off",
      "no-fallthrough": "warn",
      "no-mixed-spaces-and-tabs": "warn",
      "no-redeclare": "warn",
      "no-undef": "error",
      "no-unreachable": "warn",
      "no-useless-escape": "warn",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      "no-extend-native": "error",
      "no-proto": "error",
      "no-with": "error",
      "no-caller": "error",
      "no-iterator": "error",
      "no-var": "warn",
      "eqeqeq": ["warn", "smart"],
      "curly": ["warn", "multi-line"],
      "default-case": "warn",

      // ===== Security plugin (SAST for Node.js) =====
      "security/detect-object-injection": "off", // too noisy for TS code
      "security/detect-non-literal-regexp": "warn",
      "security/detect-non-literal-fs-filename": "off", // dynamic paths are common
      "security/detect-unsafe-regex": "warn",
      "security/detect-buffer-noassert": "error",
      "security/detect-pseudoRandomBytes": "error",
      "security/detect-new-buffer": "error",
      "security/detect-eval-with-expression": "error",
      "security/detect-non-literal-require": "warn",
      "security/detect-child-process": "warn",
      "security/detect-disable-mustache-escape": "error",
      "security/detect-no-anti-csrf": "off",
      "security/detect-possible-timing-attacks": "warn",

      // ===== No-unsanitized (XSS prevention) =====
      "no-unsanitized/method": "error",
      "no-unsanitized/property": "error",
    },
  },
  {
    ignores: [
      "node_modules/**",
      ".next/**",
      "out/**",
      "build/**",
      "next-env.d.ts",
      "examples/**",
      "skills/**",
      "scripts/**",
      "playwright-report/**",
      "test-results/**",
      "coverage/**",
      "src-mobile/**",
      "src-desktop/**",
      "src/extension/**",
      "src/sdk/**",
      "mini-services/**",
    ],
  },
];

export default eslintConfig;
