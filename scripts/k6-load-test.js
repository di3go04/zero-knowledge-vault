// k6 load test for Zero-Knowledge Vault
// Run with: k6 run scripts/k6-load-test.js

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate } from "k6/metrics";

const errorRate = new Rate("errors");

export const options = {
  stages: [
    { duration: "30s", target: 20 }, // Ramp up to 20 users
    { duration: "1m", target: 50 }, // Ramp to 50 users
    { duration: "30s", target: 100 }, // Spike to 100 users
    { duration: "30s", target: 0 }, // Ramp down
  ],
  thresholds: {
    errors: ["rate<0.1"], // Error rate must be below 10%
    http_req_duration: ["p(95)<2000"], // 95% of requests under 2s
  },
};

const BASE_URL = __ENV.BASE_URL || "http://localhost:3000";

export default function () {
  // Health check (no auth required)
  const healthResp = http.get(`${BASE_URL}/api/health`);
  check(healthResp, {
    "health status is 200": (r) => r.status === 200,
  });
  errorRate.add(healthResp.status !== 200);

  sleep(1);

  // Login attempt (no auth required, will be rejected but tests rate limiting)
  const loginResp = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({
      email: `loadtest-${__VU}@example.com`,
      masterPasswordHash: "test-hash",
    }),
    { headers: { "Content-Type": "application/json" } }
  );

  // May get 401 (invalid creds) or 429 (rate limited), both are "expected"
  check(loginResp, {
    "login responded": (r) => r.status >= 200 && r.status < 500,
  });
  errorRate.add(loginResp.status >= 500);

  sleep(2);
}
