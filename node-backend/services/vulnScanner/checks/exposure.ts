import crypto from 'crypto';
import { CheckDefinition, STANDARD_UP, COMPREHENSIVE_ONLY, result, inconclusive } from '../context';
import { makeFinding, REF } from '../findings';
import { header, ProbeError } from '../safeHttp';
import { Finding, Severity } from '../types';

/**
 * Information disclosure & exposed resources (standard + comprehensive).
 *
 * Exposed paths are only reported when the response matches a content signature
 * that is specific to that file type (e.g. ".git/HEAD" must start with
 * "ref: refs/heads/"), so soft-404 pages and catch-all routes do not produce
 * false positives. Only status, size, content type and the matched signature
 * name are kept — file contents are never stored or displayed.
 */

const STACK_TRACE_SIGNATURES: Array<{ name: string; re: RegExp }> = [
  { name: 'Python traceback', re: /Traceback \(most recent call last\)/ },
  { name: 'Django debug page', re: /You're seeing this error because you have <code>DEBUG = True<\/code>/ },
  { name: 'Java stack trace', re: /\bat (java|javax|org\.springframework|org\.apache)\.[\w.$]+\(/ },
  { name: 'ASP.NET error page', re: /(Server Error in '\/' Application|ASP\.NET is configured to show verbose error messages)/ },
  { name: 'PHP error with file path', re: /(Fatal error|Warning|Parse error)<\/b>:.+ in <b>[^<]+\.php<\/b> on line/ },
  { name: 'Laravel / Symfony debug page', re: /(Whoops! There was an error|Symfony\\Component\\[A-Za-z\\]+Exception)/ },
  { name: 'Node.js stack trace', re: /\n\s+at [\w.<>]+ \((?:\/|[A-Z]:\\)[^)]+\.js:\d+:\d+\)/ },
  { name: 'Ruby on Rails error page', re: /(Action Controller: Exception caught|ActiveRecord::\w+Error)/ },
];

const DIRECTORY_LISTING = /<title>\s*(Index of \/|Directory listing for \/)/i;

interface ExposedPath {
  path: string;
  name: string;
  severity: Severity;
  signature: RegExp;
  impact: string;
  profile: 'standard' | 'comprehensive';
}

const EXPOSED_PATHS: ExposedPath[] = [
  { path: '/.env', name: 'Environment file (.env)', severity: 'high', signature: /^(?:\s*#.*\n)*\s*[A-Z][A-Z0-9_]{1,60}\s*=.*\n\s*[A-Z][A-Z0-9_]{1,60}\s*=/m, impact: 'Environment files usually contain database passwords, API keys and secrets.', profile: 'standard' },
  { path: '/.git/HEAD', name: 'Git repository metadata', severity: 'high', signature: /^ref: refs\/heads\/[\w./-]+\s*$/m, impact: 'An exposed .git directory can allow the full source code and history (including committed secrets) to be downloaded.', profile: 'standard' },
  { path: '/.git/config', name: 'Git configuration', severity: 'high', signature: /^\[core\]\s*$/m, impact: 'Reveals repository configuration and confirms that .git is browsable.', profile: 'standard' },
  { path: '/server-status', name: 'Apache server-status page', severity: 'medium', signature: /<title>Apache Status<\/title>|Apache Server Status for/i, impact: 'Shows live requests, client IPs and internal URLs.', profile: 'standard' },
  { path: '/phpinfo.php', name: 'phpinfo() page', severity: 'medium', signature: /<title>(PHP \d[\d.]* - )?phpinfo\(\)<\/title>/i, impact: 'Discloses PHP configuration, modules, paths and environment variables.', profile: 'standard' },
  { path: '/info.php', name: 'phpinfo() page', severity: 'medium', signature: /<title>(PHP \d[\d.]* - )?phpinfo\(\)<\/title>/i, impact: 'Discloses PHP configuration, modules, paths and environment variables.', profile: 'standard' },
  { path: '/.DS_Store', name: 'macOS .DS_Store file', severity: 'low', signature: /^\x00\x00\x00\x01Bud1/, impact: 'Lists file and folder names of the directory, revealing hidden resources.', profile: 'standard' },
  { path: '/actuator/env', name: 'Spring Boot actuator /env', severity: 'high', signature: /"(propertySources|activeProfiles)"\s*:/, impact: 'Exposes application configuration and can leak credentials.', profile: 'standard' },
  { path: '/web.config', name: 'IIS web.config', severity: 'medium', signature: /<configuration[\s>][\s\S]*<system\.web/i, impact: 'Discloses server configuration and sometimes connection strings.', profile: 'standard' },
  { path: '/.htaccess', name: 'Apache .htaccess', severity: 'low', signature: /^\s*(RewriteEngine|RewriteRule|Deny from|Require all|AuthType|<IfModule)/im, impact: 'Reveals rewrite rules and protected paths.', profile: 'standard' },
  { path: '/.git/index', name: 'Git index file', severity: 'high', signature: /^DIRC/, impact: 'Lists every tracked file path of the repository.', profile: 'comprehensive' },
  { path: '/.svn/entries', name: 'Subversion metadata', severity: 'medium', signature: /^(\d+\s*\n|<\?xml[\s\S]*<wc-entries)/, impact: 'Allows source code paths and history to be reconstructed.', profile: 'comprehensive' },
  { path: '/server-info', name: 'Apache server-info page', severity: 'medium', signature: /Apache Server Information/i, impact: 'Discloses loaded modules and full server configuration.', profile: 'comprehensive' },
  { path: '/actuator/heapdump', name: 'Spring Boot heap dump endpoint', severity: 'high', signature: /^JAVA PROFILE/, impact: 'A heap dump contains in-memory secrets, sessions and personal data.', profile: 'comprehensive' },
  { path: '/elmah.axd', name: 'ELMAH error log', severity: 'medium', signature: /Error Log for .+ on /i, impact: 'Shows application exceptions, stack traces and sometimes cookies.', profile: 'comprehensive' },
  { path: '/trace.axd', name: 'ASP.NET trace viewer', severity: 'medium', signature: /<title>Application Trace<\/title>/i, impact: 'Shows request details, including headers and form values.', profile: 'comprehensive' },
  { path: '/backup.sql', name: 'SQL dump file', severity: 'high', signature: /(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)/i, impact: 'Database dumps contain user data and password hashes.', profile: 'comprehensive' },
  { path: '/dump.sql', name: 'SQL dump file', severity: 'high', signature: /(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)/i, impact: 'Database dumps contain user data and password hashes.', profile: 'comprehensive' },
  { path: '/composer.lock', name: 'Composer lock file', severity: 'low', signature: /"packages"\s*:\s*\[/, impact: 'Reveals exact dependency versions, simplifying targeted attacks.', profile: 'comprehensive' },
  { path: '/package.json', name: 'Node.js package manifest', severity: 'low', signature: /"(dependencies|devDependencies)"\s*:\s*\{/, impact: 'Reveals dependency versions and scripts.', profile: 'comprehensive' },
  { path: '/crossdomain.xml', name: 'Permissive Flash crossdomain policy', severity: 'low', signature: /<allow-access-from\s+domain="\*"/i, impact: 'Legacy plugins could read data cross-domain.', profile: 'comprehensive' },
  { path: '/.well-known/security.txt', name: 'security.txt', severity: 'info', signature: /^\s*Contact:/im, impact: 'Positive: a vulnerability disclosure contact is published.', profile: 'comprehensive' },
];

const LISTING_DIRS = ['/', '/images/', '/uploads/', '/files/', '/backup/', '/static/'];

const hashSnippet = (text: string) => crypto.createHash('sha1').update(text.replace(/\d+/g, '').slice(0, 2000)).digest('hex');

export const disclosureCheck: CheckDefinition = {
  id: 'information-disclosure',
  label: 'Information disclosure (banners, errors, listings)',
  phase: 'Information Disclosure',
  profiles: STANDARD_UP,
  async run(ctx) {
    const base = ctx.data.base;
    if (!base) return inconclusive('No response available.');
    const origin = new URL(base.url).origin;
    const findings: Finding[] = [];

    // 1. Version banners in response headers.
    const banners = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-runtime']
      .map((name) => ({ name, value: header(base, name) || '' }))
      .filter((b) => b.value && (/\d+\.\d+/.test(b.value) || b.name !== 'server'));
    if (banners.length) {
      findings.push(makeFinding({
        checkId: 'information-disclosure', key: 'banners', title: 'Software versions disclosed in response headers',
        category: 'Information Disclosure', owasp: 'A05:2021 Security Misconfiguration', severity: 'low', confidence: 'high', verification: 'misconfiguration',
        description: `The server reveals software details: ${banners.map((b) => `${b.name}: ${b.value}`).join(' · ')}.`,
        affected: base.url, evidence: banners.map((b) => ({ label: b.name, value: b.value })),
        detection: 'Inspected response headers of the target page.',
        impact: 'Exact versions let attackers quickly look up known vulnerabilities for this software.',
        remediation: 'Hide version details (nginx: server_tokens off; Apache: ServerTokens Prod; remove X-Powered-By).',
        references: [REF.owaspA05],
      }));
    }

    // 2. Error page behaviour (random, non-existent path) — also the soft-404 baseline.
    const randomPath = `/rakshak-${crypto.randomBytes(6).toString('hex')}`;
    try {
      const notFound = await ctx.http.request(`${origin}${randomPath}`, { maxBytes: 128 * 1024 });
      ctx.data.notFoundBaseline = { status: notFound.status, length: notFound.body.length, snippetHash: hashSnippet(notFound.body) };
      const trace = STACK_TRACE_SIGNATURES.find((s) => s.re.test(notFound.body));
      if (trace) {
        findings.push(makeFinding({
          checkId: 'information-disclosure', key: 'stack-trace', title: `Detailed error page exposed (${trace.name})`,
          category: 'Information Disclosure', owasp: 'A05:2021 Security Misconfiguration', severity: 'medium', confidence: 'high', verification: 'confirmed',
          description: `Requesting a non-existent page returned a ${trace.name}, which reveals internal implementation details.`,
          affected: `${origin}${randomPath}`, evidence: [{ label: 'HTTP status', value: String(notFound.status) }, { label: 'Signature matched', value: trace.name }],
          detection: 'GET request to a random non-existent path; response matched a debug/stack-trace signature (content not stored).',
          impact: 'Stack traces disclose file paths, framework versions and code structure, and debug modes may expose interactive consoles.',
          remediation: 'Disable debug mode in production and return generic error pages.',
          references: [REF.owaspA05],
        }));
      }
      if (notFound.status === 200) {
        ctx.data.limitations.push('The server returns HTTP 200 for non-existent pages (soft 404); exposed-path results rely on content signatures.');
      }
    } catch (err) {
      if (err instanceof ProbeError && err.code === 'CANCELLED') throw err;
      ctx.data.notFoundBaseline = null;
    }

    // 3. Directory listing on a few common directories.
    for (const dir of LISTING_DIRS) {
      try {
        const res = dir === '/' && new URL(base.url).pathname === '/' ? base : await ctx.http.request(`${origin}${dir}`, { maxBytes: 32 * 1024 });
        if (res.status === 200 && DIRECTORY_LISTING.test(res.body)) {
          findings.push(makeFinding({
            checkId: 'information-disclosure', key: `listing-${dir}`, title: `Directory listing enabled (${dir})`,
            category: 'Information Disclosure', owasp: 'A01:2021 Broken Access Control', severity: 'medium', confidence: 'high', verification: 'confirmed',
            description: `The web server returns an automatic file index for ${dir}.`,
            affected: `${origin}${dir}`, evidence: [{ label: 'HTTP status', value: String(res.status) }, { label: 'Page title', value: (res.body.match(/<title>([^<]{0,80})<\/title>/i) || [])[1] || 'Index of' }],
            detection: 'GET request; response title matched a directory-index signature (file names not stored).',
            impact: 'Visitors can browse every file in the directory, including backups or uploads that were never meant to be public.',
            remediation: 'Disable automatic indexes (Apache: Options -Indexes; nginx: autoindex off).',
            references: [REF.owaspA01],
          }));
        }
      } catch (err) {
        if (err instanceof ProbeError && err.code === 'CANCELLED') throw err;
      }
    }

    return result(findings, `${banners.length} banner(s); 404 page returned HTTP ${ctx.data.notFoundBaseline?.status ?? 'n/a'}`);
  },
};

const exposedPathsFor = (profile: string) => EXPOSED_PATHS.filter((p) => profile === 'comprehensive' || p.profile === 'standard');

export const exposedResourcesCheck: CheckDefinition = {
  id: 'exposed-resources',
  label: 'Exposed sensitive files & endpoints',
  phase: 'Exposed Resources',
  profiles: STANDARD_UP,
  async run(ctx) {
    const base = ctx.data.base;
    if (!base) return inconclusive('No response available.');
    const origin = new URL(base.url).origin;
    const findings: Finding[] = [];
    const baseline = ctx.data.notFoundBaseline;
    const paths = exposedPathsFor(ctx.profile);
    let checked = 0;

    await Promise.all(
      paths.map(async (item) => {
        try {
          // Range keeps transfers tiny even if the file exists; size is capped regardless.
          const res = await ctx.http.request(`${origin}${item.path}`, { headers: { Range: 'bytes=0-4095' }, maxBytes: 8 * 1024, timeoutMs: 7000 });
          checked += 1;
          if (res.status !== 200 && res.status !== 206) return;
          if (baseline && baseline.status === 200 && hashSnippet(res.body) === baseline.snippetHash) return; // soft 404
          if (!item.signature.test(res.body)) return;
          findings.push(makeFinding({
            checkId: 'exposed-resources', key: item.path, title: item.severity === 'info' ? `${item.name} published` : `Publicly accessible: ${item.name}`,
            category: 'Exposed Resources', owasp: item.severity === 'info' ? undefined : 'A05:2021 Security Misconfiguration',
            severity: item.severity, confidence: 'high', verification: item.severity === 'info' ? 'informational' : 'confirmed',
            description: item.severity === 'info' ? `${item.path} is available.` : `${item.path} is publicly accessible and its content matches the expected format of a ${item.name}.`,
            affected: `${origin}${item.path}`,
            evidence: [
              { label: 'HTTP status', value: String(res.status) },
              { label: 'Content-Type', value: header(res, 'content-type') || '(none)' },
              { label: 'Bytes inspected', value: String(res.body.length) },
              { label: 'Signature matched', value: item.name },
              { label: 'Content', value: 'not stored (redacted by design)' },
            ],
            detection: 'GET request with Range: bytes=0-4095; response matched a file-type signature.',
            impact: item.impact,
            remediation: item.severity === 'info' ? 'No action needed.' : `Remove ${item.path} from the web root or block it in the web server configuration, then rotate any secrets it contained.`,
            references: [REF.owaspA05],
          }));
        } catch (err) {
          if (err instanceof ProbeError && err.code === 'CANCELLED') throw err;
        }
      })
    );

    // Source maps (comprehensive): check up to 3 same-origin scripts for a matching .map file.
    if (COMPREHENSIVE_ONLY.includes(ctx.profile) && base.body) {
      const scripts = [...base.body.matchAll(/<script[^>]+src=["']([^"']+\.js)(?:\?[^"']*)?["']/gi)]
        .map((m) => { try { return new URL(m[1], base.url); } catch { return null; } })
        .filter((u): u is URL => Boolean(u) && u!.origin === origin)
        .slice(0, 3);
      for (const script of scripts) {
        try {
          const map = await ctx.http.request(`${script.href}.map`, { headers: { Range: 'bytes=0-2047' }, maxBytes: 4096, timeoutMs: 6000 });
          checked += 1;
          if ((map.status === 200 || map.status === 206) && /"version"\s*:\s*3/.test(map.body) && /"(mappings|sources)"/.test(map.body)) {
            findings.push(makeFinding({
              checkId: 'exposed-resources', key: `sourcemap-${script.pathname}`, title: 'JavaScript source map is publicly accessible',
              category: 'Exposed Resources', owasp: 'A05:2021 Security Misconfiguration', severity: 'low', confidence: 'high', verification: 'confirmed',
              description: `${script.pathname}.map is available, exposing the original (unminified) front-end source code.`,
              affected: `${script.href}.map`, evidence: [{ label: 'HTTP status', value: String(map.status) }, { label: 'Signature matched', value: 'Source map v3' }],
              detection: 'GET request for <script>.map (first 2 KB only).',
              impact: 'Readable source makes it easier to find client-side logic flaws, hidden endpoints or embedded keys.',
              remediation: 'Do not deploy .map files to production, or restrict access to them.',
              references: [REF.owaspA05],
            }));
          }
        } catch (err) {
          if (err instanceof ProbeError && err.code === 'CANCELLED') throw err;
        }
      }
    }

    return result(findings, `${checked} path(s) checked against content signatures`);
  },
};
