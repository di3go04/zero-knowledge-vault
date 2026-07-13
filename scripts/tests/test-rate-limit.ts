/**
 * test-rate-limit.ts — Test rate limiting triggers 429.
 * Run: bun scripts/tests/test-rate-limit.ts
 */
import { checkRateLimit, resetRateLimit } from "../../src/lib/rate-limit";

let passed = 0, failed = 0;
function assert(cond: boolean, msg: string) {
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.error(`  ✗ ${msg}`); }
}

console.log("\n=== Rate Limiting ===");
{
  const key = "test:rl:127.0.0.1:test@test.com";
  resetRateLimit(key);

  let results: boolean[] = [];
  for (let i = 0; i < 6; i++) {
    const r = await checkRateLimit(key, 5, 15 * 60 * 1000);
    results.push(r.allowed);
  }

  assert(results[0], "First request allowed");
  assert(results[4], "Fifth request allowed");
  assert(!results[5], "Sixth request blocked (429)");

  const r = await checkRateLimit(key, 5, 15 * 60 * 1000);
  assert(!r.allowed, "Blocked request stays blocked");
  assert(r.retryAfterSeconds > 0, "Retry-After is positive");

  resetRateLimit(key);
  const r2 = await checkRateLimit(key, 5, 15 * 60 * 1000);
  assert(r2.allowed, "After reset, requests allowed again");
}

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
