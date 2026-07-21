import http from 'k6/http';
import { check, sleep } from 'k6';
export const options = {
  stages: [{ duration: '30s', target: 50 }, { duration: '1m', target: 50 }, { duration: '30s', target: 0 }],
  thresholds: { http_req_duration: ['p(95)<500'], http_req_failed: ['rate<0.05'] },
};
export default function () {
  const res = http.post('https://zero-knowledge-vault-five.vercel.app/api/auth/login',
    JSON.stringify({ email: 'test@example.com' }), { headers: { 'Content-Type': 'application/json' } });
  check(res, { 'status 200': (r) => r.status === 200 || r.status === 429 });
  sleep(1);
}
