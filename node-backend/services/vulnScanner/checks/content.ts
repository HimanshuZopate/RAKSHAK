import { CheckDefinition, STANDARD_UP, result, skipped } from '../context';
import { makeFinding, REF } from '../findings';
import { isHtml } from '../safeHttp';
import { Finding } from '../types';

/**
 * HTML content analysis (standard + comprehensive), using the already retrieved
 * target page (no extra requests):
 *  - active mixed content (script/iframe/stylesheet over HTTP on an HTTPS page)
 *  - passive mixed content (img/audio/video over HTTP)
 *  - forms submitting to http:// and password fields on plain-HTTP pages
 */

const attrUrls = (html: string, tag: RegExp, attr: string) =>
  [...html.matchAll(new RegExp(`<(${tag.source})\\b[^>]*\\s${attr}\\s*=\\s*["']?(http:\\/\\/[^"'\\s>]+)`, 'gi'))].map((m) => ({ tag: m[1].toLowerCase(), url: m[2] }));

export const contentCheck: CheckDefinition = {
  id: 'page-content',
  label: 'Mixed content & insecure forms',
  phase: 'Content Analysis',
  profiles: STANDARD_UP,
  async run(ctx) {
    const base = ctx.data.base;
    if (!base || !isHtml(base) || !base.body) return skipped('The target did not return an HTML page.');
    const html = base.body;
    const pageIsHttps = base.url.startsWith('https:');
    const findings: Finding[] = [];
    const common = { checkId: 'page-content', affected: base.url, references: [REF.owaspA02] };

    if (pageIsHttps) {
      const stylesheets = [...html.matchAll(/<link\b[^>]*>/gi)]
        .map((m) => m[0])
        .filter((tag) => /\srel\s*=\s*["']?stylesheet/i.test(tag))
        .map((tag) => (tag.match(/\shref\s*=\s*["']?(http:\/\/[^"'\s>]+)/i) || [])[1])
        .filter((url): url is string => Boolean(url))
        .map((url) => ({ tag: 'link', url }));
      const active = [...attrUrls(html, /script|iframe|frame|embed/, 'src'), ...stylesheets];
      const passive = attrUrls(html, /img|audio|video|source/, 'src');
      if (active.length) {
        findings.push(makeFinding({
          ...common, key: 'active-mixed', title: 'Active mixed content (scripts/frames loaded over HTTP)', category: 'Mixed Content', owasp: 'A02:2021 Cryptographic Failures',
          severity: 'medium', confidence: 'high', verification: 'confirmed',
          description: `The HTTPS page references ${active.length} script/frame/stylesheet resource(s) over plain HTTP. Modern browsers block these, which can also break the page.`,
          evidence: active.slice(0, 6).map((r) => ({ label: `<${r.tag}>`, value: r.url })),
          detection: 'Parsed the HTML of the HTTPS page for http:// resource references.',
          impact: 'In browsers that load them, a network attacker can replace these scripts and take over the page.',
          remediation: 'Load every resource over HTTPS (or protocol-relative/same-origin paths) and consider CSP upgrade-insecure-requests.',
        }));
      }
      if (passive.length) {
        findings.push(makeFinding({
          ...common, key: 'passive-mixed', title: 'Passive mixed content (images/media over HTTP)', category: 'Mixed Content',
          severity: 'low', confidence: 'high', verification: 'confirmed',
          description: `The HTTPS page loads ${passive.length} image/media resource(s) over plain HTTP.`,
          evidence: passive.slice(0, 6).map((r) => ({ label: `<${r.tag}>`, value: r.url })),
          detection: 'Parsed the HTML of the HTTPS page for http:// resource references.',
          impact: 'Attackers on the network can swap images (e.g. fake content) and observe which pages are viewed.',
          remediation: 'Serve all media over HTTPS.',
        }));
      }
    }

    const insecureForms = [...html.matchAll(/<form\b[^>]*\saction\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi)].map((m) => m[1]);
    if (insecureForms.length) {
      findings.push(makeFinding({
        ...common, key: 'form-http-action', title: 'Form submits data over plain HTTP', category: 'Mixed Content', owasp: 'A02:2021 Cryptographic Failures',
        severity: 'medium', confidence: 'high', verification: 'confirmed',
        description: `${insecureForms.length} form(s) post to an http:// address.`,
        evidence: insecureForms.slice(0, 5).map((u) => ({ label: 'form action', value: u })),
        detection: 'Parsed <form action> attributes of the target page.',
        impact: 'Anything the user types into these forms is sent unencrypted.',
        remediation: 'Change form actions to HTTPS URLs.',
      }));
    }

    if (!pageIsHttps && /<input\b[^>]*type\s*=\s*["']?password/i.test(html)) {
      findings.push(makeFinding({
        ...common, key: 'password-over-http', title: 'Password field on a page served over HTTP', category: 'Transport Security', owasp: 'A02:2021 Cryptographic Failures',
        severity: 'high', confidence: 'high', verification: 'confirmed',
        description: 'The page contains a password input but was delivered over unencrypted HTTP.',
        evidence: [{ label: 'Page URL', value: base.url }, { label: 'Element', value: '<input type="password">' }],
        detection: 'Parsed the HTML of the HTTP page.',
        impact: 'Credentials typed on this page can be captured by anyone on the network path, and the page itself can be modified to steal them.',
        remediation: 'Serve the login page (and the whole site) over HTTPS only.',
      }));
    }

    return result(findings, `${html.length.toLocaleString()} bytes of HTML analysed`);
  },
};
