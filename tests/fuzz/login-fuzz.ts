/** Fuzzing payloads for /api/auth/login */
export const fuzzPayloads = [
  { email: "", name: "empty email" },
  { email: "a".repeat(10000) + "@x.com", name: "very long email" },
  { email: "test@example.com\x00admin", name: "null byte injection" },
  { email: "test@example.com\r\nX-Injected: true", name: "CRLF injection" },
  { email: "' OR 1=1 --", name: "SQL injection" },
  { email: "<script>alert(1)</script>@x.com", name: "XSS in email" },
  { email: "../../etc/passwd", name: "path traversal" },
  { email: "test@example.com", name: "valid email" },
];
