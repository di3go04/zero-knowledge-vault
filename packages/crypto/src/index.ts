/**
 * @zk-vault/crypto — Public API
 *
 * This package is a thin re-export of the canonical crypto module at
 * src/lib/crypto. In the monorepo workspace, the root tsconfig path
 * alias "@/*" → "./src/*" resolves the imports at build time, so we
 * don't duplicate any source files here.
 *
 * To consume the crypto module standalone (outside this monorepo),
 * copy the src/lib/crypto/ directory into your project.
 */
export * from "../../src/lib/crypto";
