import { CheckDefinition, ALL_PROFILES, result, inconclusive } from '../context';
import { makeFinding, REF } from '../findings';
import { header, isHtml } from '../safeHttp';
import { Finding } from '../types';

/**
 * Security header analysis (all profiles).
 *
 * Severity rubric used here:
 *  - medium: a missing/weak control that removes a primary browser defence for an
 *            HTML page (CSP, clickjacking protection, HSTS on an HTTPS site)
 *  - low:    defence-in-depth controls (nosniff, referrer policy, weak values)
 *  - info:   optional hardening headers whose absence is not a vulnerability
 * A missing header is reported as a misconfiguration, never as a confirmed vulnerability.
 */

export type CspDirectives = Map<string, string[]>;

export const parseCsp = (value: string): CspDirectives => {
  const directives: CspDirectives = new Map();
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1)); // first occurrence wins (CSP spec)
  }
  return directives;
};

export interface CspWeakness {
  key: string;
  title: string;
  severity: 'medium' | 'low' | 'info';
  detail: string;
}

/** Evaluates the script-execution related weaknesses of a CSP. */
export const analyzeCsp = (directives: CspDirectives): CspWeakness[] => {
  const weaknesses: CspWeakness[] = [];
  const scriptSrc = directives.get('script-src') ?? directives.get('default-src');
  const scriptDirective = directives.has('script-src') ? 'script-src' : 'default-src';

  if (!scriptSrc) {
    weaknesses.push({
      key: 'no-script-src',
      title: 'CSP does not restrict script sources',
      severity: 'medium',
      detail: 'Neither script-src nor default-src is defined, so the policy does not limit where scripts can load from.',
    });
  } else {
    const lower = scriptSrc.map((t) => t.toLowerCase());
    const hasNonceOrHash = lower.some((t) => /^'(nonce-|sha256-|sha384-|sha512-)/.test(t));
    const hasStrictDynamic = lower.includes("'strict-dynamic'");
    if (lower.includes("'unsafe-inline'") && !hasNonceOrHash) {
      weaknesses.push({
        key: 'unsafe-inline',
        title: "CSP allows inline scripts ('unsafe-inline')",
        severity: 'medium',
        detail: `${scriptDirective} contains 'unsafe-inline' without a nonce or hash, so injected inline scripts would still run.`,
      });
    }
    if (lower.includes("'unsafe-eval'")) {
      weaknesses.push({
        key: 'unsafe-eval',
        title: "CSP allows eval() ('unsafe-eval')",
        severity: 'low',
        detail: `${scriptDirective} contains 'unsafe-eval', permitting string-to-code functions such as eval().`,
      });
    }
    const broad = lower.filter((t) => t === '*' || t === 'http:' || t === 'https:' || t === 'data:');
    if (broad.length && !hasStrictDynamic) {
      weaknesses.push({
        key: 'broad-source',
        title: 'CSP allows scripts from overly broad sources',
        severity: 'medium',
        detail: `${scriptDirective} allows ${broad.join(', ')}, which lets scripts load from (almost) any origin.`,
      });
    }
  }
  if (!directives.has('object-src') && !directives.get('default-src')?.some((t) => t === "'none'")) {
    weaknesses.push({
      key: 'no-object-src',
      title: "CSP does not set object-src 'none'",
      severity: 'low',
      detail: 'Plugin content (object/embed) is not restricted; the recommended value is object-src \'none\'.',
    });
  }
  if (!directives.has('base-uri')) {
    weaknesses.push({
      key: 'no-base-uri',
      title: 'CSP does not restrict base-uri',
      severity: 'info',
      detail: 'Without base-uri, an injected <base> tag could redirect relative script URLs.',
    });
  }
  return weaknesses;
};

const HSTS_MIN_RECOMMENDED = 15552000; // 180 days

export const headersCheck: CheckDefinition = {
  id: 'security-headers',
  label: 'HTTP security headers',
  phase: 'HTTP Headers',
  profiles: ALL_PROFILES,
  async run(ctx) {
    const base = ctx.data.base;
    if (!base) return inconclusive('No response available to analyse.');
    const findings: Finding[] = [];
    const url = base.url;
    const html = isHtml(base);
    const https = url.startsWith('https:');
    const h = (name: string) => header(base, name);

    ctx.data.headerSnapshot = {
      url,
      status: base.status,
      headers: Object.fromEntries(
        [
          'content-security-policy', 'content-security-policy-report-only', 'strict-transport-security',
          'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy',
          'cross-origin-opener-policy', 'cross-origin-resource-policy', 'cross-origin-embedder-policy',
          'server', 'x-powered-by', 'content-type',
        ].map((name) => [name, h(name) ?? ''])
      ),
    };

    const add = (input: Omit<Parameters<typeof makeFinding>[0], 'checkId' | 'affected' | 'category'> & { category?: string }) =>
      findings.push(makeFinding({ checkId: 'security-headers', affected: url, category: input.category ?? 'Security Headers', ...input }));

    // ── Content-Security-Policy ────────────────────────────────────────────
    const csp = h('content-security-policy');
    const cspReportOnly = h('content-security-policy-report-only');
    if (html) {
      if (!csp) {
        add({
          key: 'csp-missing',
          title: cspReportOnly ? 'Content-Security-Policy is only in report-only mode' : 'Content-Security-Policy header is missing',
          owasp: 'A05:2021 Security Misconfiguration',
          severity: cspReportOnly ? 'low' : 'medium',
          confidence: 'high',
          verification: 'misconfiguration',
          description: cspReportOnly
            ? 'A policy is sent as Content-Security-Policy-Report-Only, which reports violations but does not block anything.'
            : 'The HTML response does not define a Content Security Policy.',
          evidence: [{ label: 'Content-Security-Policy', value: '(not present)' }, ...(cspReportOnly ? [{ label: 'Report-Only policy', value: cspReportOnly }] : [])],
          detection: 'Inspected the response headers of the target page.',
          impact: 'If the site has an XSS flaw, the browser has no policy to stop injected scripts. This is a missing defence, not proof of XSS.',
          remediation: "Define a policy such as default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self' and tighten it for your assets.",
          references: [REF.mdnCsp, REF.owaspHeaders],
        });
      } else {
        for (const weakness of analyzeCsp(parseCsp(csp))) {
          add({
            key: `csp-${weakness.key}`,
            title: weakness.title,
            owasp: 'A05:2021 Security Misconfiguration',
            severity: weakness.severity,
            confidence: 'high',
            verification: weakness.severity === 'info' ? 'informational' : 'misconfiguration',
            description: weakness.detail,
            evidence: [{ label: 'Content-Security-Policy', value: csp }],
            detection: 'Parsed the Content-Security-Policy directives of the target page.',
            impact: 'The policy is weaker than it appears and may not stop injected scripts.',
            remediation: "Use nonces or hashes instead of 'unsafe-inline', avoid 'unsafe-eval' and broad sources, and add object-src 'none' and base-uri 'self'.",
            references: [REF.mdnCsp],
          });
        }
      }
    }

    // ── Strict-Transport-Security ──────────────────────────────────────────
    if (https) {
      const hsts = h('strict-transport-security');
      if (!hsts) {
        add({
          key: 'hsts-missing',
          title: 'Strict-Transport-Security (HSTS) header is missing',
          category: 'Transport Security',
          owasp: 'A02:2021 Cryptographic Failures',
          severity: 'medium',
          confidence: 'high',
          verification: 'misconfiguration',
          description: 'The HTTPS response does not instruct browsers to always use HTTPS for this host.',
          evidence: [{ label: 'Strict-Transport-Security', value: '(not present)' }],
          detection: 'Inspected the response headers of the HTTPS page.',
          impact: 'A user’s first plain-HTTP request can be intercepted and downgraded (SSL stripping).',
          remediation: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains once the whole site works over HTTPS.',
          references: [REF.mdnHsts],
        });
      } else {
        const match = hsts.match(/max-age\s*=\s*"?(\d+)"?/i);
        const maxAge = match ? Number(match[1]) : null;
        if (maxAge === null) {
          add({
            key: 'hsts-invalid', title: 'HSTS header has no valid max-age', category: 'Transport Security', severity: 'low', confidence: 'high',
            verification: 'misconfiguration', description: 'The Strict-Transport-Security header is present but lacks a valid max-age directive, so browsers ignore it.',
            evidence: [{ label: 'Strict-Transport-Security', value: hsts }], detection: 'Parsed the HSTS header.',
            impact: 'HSTS protection is not actually enabled.', remediation: 'Use Strict-Transport-Security: max-age=31536000; includeSubDomains.', references: [REF.mdnHsts],
          });
        } else if (maxAge < HSTS_MIN_RECOMMENDED) {
          add({
            key: 'hsts-short', title: 'HSTS max-age is short', category: 'Transport Security', severity: maxAge === 0 ? 'medium' : 'low', confidence: 'high',
            verification: 'misconfiguration',
            description: maxAge === 0 ? 'max-age=0 tells browsers to forget the HSTS policy.' : `max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days); at least 180 days is recommended.`,
            evidence: [{ label: 'Strict-Transport-Security', value: hsts }], detection: 'Parsed the HSTS header.',
            impact: 'Browsers stop enforcing HTTPS soon after a visit, re-opening the downgrade window.', remediation: 'Increase max-age to at least 15552000 (180 days), ideally 31536000.', references: [REF.mdnHsts],
          });
        } else if (!/includesubdomains/i.test(hsts)) {
          add({
            key: 'hsts-no-subdomains', title: 'HSTS does not include subdomains', category: 'Transport Security', severity: 'info', confidence: 'high',
            verification: 'informational', description: 'The HSTS policy covers only this host, not its subdomains.',
            evidence: [{ label: 'Strict-Transport-Security', value: hsts }], detection: 'Parsed the HSTS header.',
            impact: 'Subdomains can still be reached over HTTP unless they send their own HSTS header.', remediation: 'Add includeSubDomains once all subdomains support HTTPS.', references: [REF.mdnHsts],
          });
        }
      }
    }

    // ── Clickjacking protection ────────────────────────────────────────────
    if (html) {
      const xfo = (h('x-frame-options') || '').trim().toUpperCase();
      const frameAncestors = csp ? parseCsp(csp).get('frame-ancestors') : undefined;
      const xfoValid = xfo === 'DENY' || xfo === 'SAMEORIGIN';
      if (!frameAncestors && !xfoValid) {
        add({
          key: 'clickjacking',
          title: xfo ? `X-Frame-Options value "${xfo}" is not effective` : 'No clickjacking protection (X-Frame-Options / frame-ancestors)',
          owasp: 'A05:2021 Security Misconfiguration',
          severity: 'medium',
          confidence: 'high',
          verification: 'misconfiguration',
          description: xfo
            ? `X-Frame-Options is set to "${xfo}", which modern browsers do not support (only DENY and SAMEORIGIN are honoured), and CSP frame-ancestors is not set.`
            : 'The page can be embedded in a frame on any website because neither X-Frame-Options nor CSP frame-ancestors is set.',
          evidence: [{ label: 'X-Frame-Options', value: xfo || '(not present)' }, { label: 'CSP frame-ancestors', value: '(not present)' }],
          detection: 'Inspected X-Frame-Options and the CSP frame-ancestors directive of the HTML response.',
          impact: 'An attacker page can overlay this site in an invisible frame and trick users into clicking buttons (clickjacking).',
          remediation: "Send Content-Security-Policy: frame-ancestors 'self' (and X-Frame-Options: SAMEORIGIN for older browsers).",
          references: [REF.owaspHeaders],
        });
      }
    }

    // ── X-Content-Type-Options ─────────────────────────────────────────────
    const xcto = (h('x-content-type-options') || '').trim().toLowerCase();
    if (xcto !== 'nosniff') {
      add({
        key: 'nosniff',
        title: 'X-Content-Type-Options: nosniff is not set',
        owasp: 'A05:2021 Security Misconfiguration',
        severity: 'low',
        confidence: 'high',
        verification: 'misconfiguration',
        description: xcto ? `X-Content-Type-Options has the unsupported value "${xcto}".` : 'The response does not send X-Content-Type-Options: nosniff.',
        evidence: [{ label: 'X-Content-Type-Options', value: xcto || '(not present)' }],
        detection: 'Inspected the response headers.',
        impact: 'Browsers may MIME-sniff responses, which can turn uploaded or user-controlled files into executable content.',
        remediation: 'Send X-Content-Type-Options: nosniff on all responses.',
        references: [REF.owaspHeaders],
      });
    }

    // ── Referrer-Policy ────────────────────────────────────────────────────
    const referrer = (h('referrer-policy') || '').trim().toLowerCase();
    if (referrer.split(',').map((v) => v.trim()).includes('unsafe-url')) {
      add({
        key: 'referrer-unsafe', title: 'Referrer-Policy leaks full URLs (unsafe-url)', severity: 'low', confidence: 'high', verification: 'misconfiguration',
        description: 'Referrer-Policy: unsafe-url sends the full URL, including path and query string, to every destination, even over HTTP.',
        evidence: [{ label: 'Referrer-Policy', value: referrer }], detection: 'Inspected the Referrer-Policy header.',
        impact: 'Tokens or personal data in URLs can leak to third-party sites.', remediation: 'Use Referrer-Policy: strict-origin-when-cross-origin or no-referrer.', references: [REF.owaspHeaders],
      });
    } else if (!referrer && html) {
      add({
        key: 'referrer-missing', title: 'Referrer-Policy header is not set', severity: 'info', confidence: 'high', verification: 'informational',
        description: 'No Referrer-Policy is sent. Modern browsers default to strict-origin-when-cross-origin, so this is a hardening recommendation.',
        evidence: [{ label: 'Referrer-Policy', value: '(not present)' }], detection: 'Inspected the response headers.',
        impact: 'Older browsers may send full URLs as the Referer to other sites.', remediation: 'Send Referrer-Policy: strict-origin-when-cross-origin.', references: [REF.owaspHeaders],
      });
    }

    // ── Optional hardening headers (informational) ─────────────────────────
    if (html) {
      const missing = ['permissions-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy'].filter((n) => !h(n));
      if (missing.length) {
        add({
          key: 'optional-hardening',
          title: 'Optional browser-isolation headers are not set',
          severity: 'info',
          confidence: 'high',
          verification: 'informational',
          description: `Not set: ${missing.join(', ')}. Cross-Origin-Embedder-Policy is only needed for cross-origin isolation and is not assessed as missing.`,
          evidence: missing.map((n) => ({ label: n, value: '(not present)' })),
          detection: 'Inspected the response headers.',
          impact: 'These headers reduce cross-origin attack surface (e.g. Spectre-style leaks, unwanted feature access); their absence is not a vulnerability.',
          remediation: 'Consider Permissions-Policy (disable unused features), Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: same-site.',
          references: [REF.owaspHeaders],
        });
      }
    }

    return result(findings, `${html ? 'HTML' : 'non-HTML'} response analysed (${base.status})`);
  },
};
