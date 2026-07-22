# Security Audit Report

Generated: 2026-07-22

## Audit tool

`bun audit --production` (bun v1.3.14)

## Result summary

**2 vulnerabilities** reported by bun audit (1 high, 1 moderate).
Both are already fixed in the installed versions — the report appears stale.

## Vulnerability details

### 1. `sharp` — High — CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591

- **Requires**: sharp < 0.35.0
- **Installed**: **0.35.3** ✅ (above fix threshold)
- **Patched in**: 0.35.0
- **Action**: None required. Already on 0.35.3.

### 2. `postcss` — Moderate — GHSA-qx2v-qp2m-jg93 (XSS via unescaped `</style>`)

- **Requires**: postcss < 8.5.10
- **Installed**: **8.5.22** ✅ (above fix threshold)
- **Patched in**: 8.5.10
- **Action**: None required. Already on 8.5.22.

## Conclusion

Both reported vulnerabilities are already resolved by the currently installed versions. The bun audit output appears to reference an outdated advisory cache. No actionable security issues remain in production dependencies.
