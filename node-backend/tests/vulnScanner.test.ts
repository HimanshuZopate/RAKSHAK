/**
 * Unit tests for the vulnerability scanner's pure logic (no network).
 * Run: npm run test:vuln
 * End-to-end behaviour is exercised against the local lab (npm run vuln-lab).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import axios from 'axios';
import { parseCsp, analyzeCsp } from '../services/vulnScanner/checks/headers';
import { parseSetCookie } from '../services/vulnScanner/checks/cookies';
import { reflectionContext } from '../services/vulnScanner/checks/activeProbes';
import { parseNvdResponse, lookupCves } from '../services/vulnScanner/checks/cveCorrelation';
import { isBlockedAddress, nat64EmbeddedIPv4, parseScanTarget, TargetRejectedError } from '../services/vulnScanner/targetGuard';
import { summarize, findingPoints } from '../services/vulnScanner/scoring';
import { makeFinding, dedupeFindings } from '../services/vulnScanner/findings';
import { Finding } from '../services/vulnScanner/types';

const finding = (over: Partial<Parameters<typeof makeFinding>[0]> = {}): Finding =>
  makeFinding({
    checkId: 'test', key: 'k', title: 'T', category: 'C', severity: 'medium', confidence: 'high', verification: 'misconfiguration',
    description: 'd', affected: 'https://example.com', evidence: [], detection: 'x', impact: 'i', remediation: 'r', ...over,
  });

test('target validation rejects unsafe URLs and normalises safe ones', () => {
  for (const bad of ['ftp://example.com', 'javascript:alert(1)', 'http://127.0.0.1', 'http://[::1]', 'http://[::ffff:127.0.0.1]', 'http://169.254.169.254',
    'http://10.1.2.3', 'http://localhost', 'http://metadata.google.internal', 'http://intranet', 'http://example.com:22', 'http://u:p@example.com', 'http://a b.com']) {
    assert.throws(() => parseScanTarget(bad), TargetRejectedError, bad);
  }
  const ok = parseScanTarget('example.com/path?x=1#frag');
  assert.equal(ok.url.href, 'https://example.com/path?x=1');
  assert.equal(ok.port, 443);
});

test('address classification blocks private, reserved and translated forms', () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '172.16.5.4', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1',
    '::1', 'fc00::1', 'fe80::1', '::ffff:7f00:1', '64:ff9b::a00:1', '2002:7f00:1::1']) {
    assert.equal(isBlockedAddress(ip), true, ip);
  }
  for (const ip of ['93.184.216.34', '104.154.89.105', '2606:4700::1111']) assert.equal(isBlockedAddress(ip), false, ip);
  assert.equal(nat64EmbeddedIPv4('64:ff9b::689a:5969'), '104.154.89.105');
  assert.equal(nat64EmbeddedIPv4('64:ff9b::a00:1'), '10.0.0.1');
  assert.equal(nat64EmbeddedIPv4('2606:4700::1'), null);
});

test('CSP analysis flags real weaknesses only', () => {
  const weak = analyzeCsp(parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:"));
  const keys = weak.map((w) => w.key);
  assert.ok(keys.includes('unsafe-inline') && keys.includes('unsafe-eval') && keys.includes('broad-source') && keys.includes('no-object-src'));
  const strong = analyzeCsp(parseCsp("default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline' 'strict-dynamic'; object-src 'none'; base-uri 'self'"));
  assert.deepEqual(strong, [], "nonce + strict-dynamic makes 'unsafe-inline' a fallback, not a weakness");
});

test('cookie parsing keeps attributes but never the value', () => {
  const c = parseSetCookie('sessionid=SECRET-VALUE-123; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600');
  assert.ok(c);
  assert.equal(c!.name, 'sessionid');
  assert.equal(c!.httpOnly, true);
  assert.equal(c!.secure, false);
  assert.equal(c!.sameSite, 'lax');
  assert.equal(c!.maxAgeSeconds, 3600);
  assert.ok(!JSON.stringify(c).includes('SECRET-VALUE-123'));
  assert.match(c!.attributeSummary, /^sessionid=<redacted>;/);
});

test('reflection context detection distinguishes encoded output', () => {
  const marker = 'rkabc';
  const payload = `${marker}"'<rkx>`;
  assert.equal(reflectionContext(`<p>${payload}</p>`, marker, payload), 'html');
  assert.equal(reflectionContext(`<input value="${payload}">`, marker, payload), 'attribute');
  assert.equal(reflectionContext(`<script>var q = "${payload}";</script>`, marker, payload), 'script');
  assert.equal(reflectionContext(`<p>${marker}&quot;&#39;&lt;rkx&gt;</p>`, marker, payload), 'encoded');
  assert.equal(reflectionContext('<p>nothing</p>', marker, payload), null);
});

test('risk score: worst finding dominates, low findings cannot add up to critical', () => {
  const lows = Array.from({ length: 30 }, (_, i) => finding({ key: `low${i}`, severity: 'low' }));
  assert.ok(summarize(lows, []).riskScore < 70, 'thirty low findings must not be critical');
  const critical = summarize([finding({ key: 'c', severity: 'critical', verification: 'confirmed' })], []);
  assert.equal(critical.riskScore, 40);
  const potential = finding({ key: 'p', severity: 'critical', verification: 'potential', confidence: 'medium' });
  assert.equal(findingPoints(potential), 16, 'potential findings are discounted by confidence');
  assert.equal(summarize([finding({ key: 'i', severity: 'info', verification: 'informational' })], []).riskScore, 0);
  const s = summarize([finding({ key: 'a' }), finding({ key: 'b', severity: 'high' })], []);
  assert.equal(s.riskScore, Math.round(100 * (1 - 0.9 * 0.75)));
  assert.equal(s.securityScore, 100 - s.riskScore);
});

test('duplicate findings collapse to the most severe instance', () => {
  const out = dedupeFindings([finding({ severity: 'low' }), finding({ severity: 'high' }), finding({ key: 'other', severity: 'medium' })]);
  assert.equal(out.length, 2);
  assert.equal(out[0].severity, 'high');
});

test('NVD response parsing sorts by CVSS and keeps the total', () => {
  const parsed = parseNvdResponse({
    totalResults: 3,
    vulnerabilities: [
      { cve: { id: 'CVE-1', published: '2021-01-01', descriptions: [{ lang: 'en', value: 'low one' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 3.1, baseSeverity: 'LOW', version: '3.1' } }] } } },
      { cve: { id: 'CVE-2', descriptions: [{ lang: 'en', value: 'critical one' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL', version: '3.1' } }] } } },
      { cve: { id: 'CVE-3', descriptions: [{ lang: 'en', value: 'v2 only' }], metrics: { cvssMetricV2: [{ baseSeverity: 'MEDIUM', cvssData: { baseScore: 5, version: '2.0' } }] } } },
    ],
  });
  assert.equal(parsed.total, 3);
  assert.deepEqual(parsed.records.map((r) => r.id), ['CVE-2', 'CVE-3', 'CVE-1']);
  assert.equal(parsed.records[0].url, 'https://nvd.nist.gov/vuln/detail/CVE-2');
});

test('NVD outage surfaces as an error (check becomes inconclusive), not as fake data', async () => {
  const original = axios.get;
  (axios as any).get = async () => { throw Object.assign(new Error('down'), { response: { status: 503 } }); };
  process.env.NVD_API_KEY = 'unit-test'; // shortens the rate-limit spacing in tests
  try {
    await assert.rejects(lookupCves('cpe:2.3:a:test:outage:1.0:*:*:*:*:*:*:*', new AbortController().signal));
  } finally {
    (axios as any).get = original;
    delete process.env.NVD_API_KEY;
  }
});
