import { CheckDefinition, STANDARD_UP, result, inconclusive } from '../context';
import { header } from '../safeHttp';
import { Confidence, TechnologyInfo } from '../types';

/**
 * Technology fingerprinting from observable evidence only (standard + comprehensive).
 * A version is recorded only when it appears explicitly (header token, generator
 * meta tag, versioned asset filename, framework attribute). Weak hints (cookie
 * names, generic paths) identify the technology but never a version.
 */

/** NVD CPE vendor:product mapping (verified against the NVD CPE dictionary). */
const CPE: Record<string, string> = {
  nginx: 'f5:nginx',
  'Apache HTTP Server': 'apache:http_server',
  PHP: 'php:php',
  jQuery: 'jquery:jquery',
  Bootstrap: 'getbootstrap:bootstrap',
  WordPress: 'wordpress:wordpress',
  'Microsoft IIS': 'microsoft:internet_information_services',
  OpenSSL: 'openssl:openssl',
  'Apache Tomcat': 'apache:tomcat',
  AngularJS: 'angularjs:angular.js',
  Drupal: 'drupal:drupal',
  lighttpd: 'lighttpd:lighttpd',
  'Eclipse Jetty': 'eclipse:jetty',
  'jQuery UI': 'jquery:jquery_ui',
  Lodash: 'lodash:lodash',
  'Moment.js': 'momentjs:moment',
};

const cleanVersion = (v: string | undefined | null) => (v && /^\d+(\.\d+){1,3}[a-z0-9-]*$/i.test(v) ? v : null);

export const fingerprintCheck: CheckDefinition = {
  id: 'fingerprint',
  label: 'Technology fingerprinting',
  phase: 'Technology Detection',
  profiles: STANDARD_UP,
  async run(ctx) {
    const base = ctx.data.base;
    if (!base) return inconclusive('No response available.');
    const found = new Map<string, TechnologyInfo>();
    const add = (name: string, category: string, version: string | null, confidence: Confidence, evidence: string) => {
      const existing = found.get(name);
      if (existing && (existing.version || !version)) return; // keep the most specific evidence
      found.set(name, { name, category, version, confidence, evidence: evidence.slice(0, 160), cpe: version && CPE[name] ? `cpe:2.3:a:${CPE[name]}:${version}:*:*:*:*:*:*:*` : undefined });
    };

    // ── Headers ────────────────────────────────────────────────────────────
    const server = header(base, 'server') || '';
    const serverTokens: Array<[RegExp, string, string]> = [
      [/nginx(?:\/([\d.]+))?/i, 'nginx', 'Web server'],
      [/openresty(?:\/([\d.]+))?/i, 'OpenResty', 'Web server'],
      [/Apache(?:\/([\d.]+))?(?!-Coyote)/i, 'Apache HTTP Server', 'Web server'],
      [/Microsoft-IIS(?:\/([\d.]+))?/i, 'Microsoft IIS', 'Web server'],
      [/LiteSpeed/i, 'LiteSpeed', 'Web server'],
      [/lighttpd(?:\/([\d.]+))?/i, 'lighttpd', 'Web server'],
      [/Jetty\(([\d.]+)/i, 'Eclipse Jetty', 'Web server'],
      [/Apache-Coyote/i, 'Apache Tomcat', 'Application server'],
      [/gunicorn(?:\/([\d.]+))?/i, 'Gunicorn', 'Application server'],
      [/Kestrel/i, 'Kestrel (ASP.NET Core)', 'Web server'],
      [/cloudflare/i, 'Cloudflare', 'CDN'],
      [/Caddy/i, 'Caddy', 'Web server'],
      [/OpenSSL\/([\d.]+[a-z]?)/i, 'OpenSSL', 'Library'],
      [/PHP\/([\d.]+)/i, 'PHP', 'Language'],
    ];
    for (const [re, name, category] of serverTokens) {
      const m = server.match(re);
      if (m) add(name, category, cleanVersion(m[1]), 'high', `Server: ${server}`);
    }
    const poweredBy = header(base, 'x-powered-by') || '';
    if (poweredBy) {
      const php = poweredBy.match(/PHP\/([\d.]+)/i);
      if (php) add('PHP', 'Language', cleanVersion(php[1]), 'high', `X-Powered-By: ${poweredBy}`);
      if (/Express/i.test(poweredBy)) add('Express', 'Web framework', null, 'high', `X-Powered-By: ${poweredBy}`);
      if (/ASP\.NET/i.test(poweredBy)) add('ASP.NET', 'Web framework', null, 'high', `X-Powered-By: ${poweredBy}`);
      if (/Next\.js/i.test(poweredBy)) add('Next.js', 'Web framework', null, 'high', `X-Powered-By: ${poweredBy}`);
    }
    const aspnet = header(base, 'x-aspnet-version');
    if (aspnet) add('ASP.NET', 'Web framework', cleanVersion(aspnet), 'high', `X-AspNet-Version: ${aspnet}`);
    if (header(base, 'cf-ray')) add('Cloudflare', 'CDN', null, 'high', 'cf-ray response header');
    if (header(base, 'x-vercel-id')) add('Vercel', 'Hosting', null, 'high', 'x-vercel-id response header');
    if (/AmazonS3/i.test(server)) add('Amazon S3', 'Hosting', null, 'high', `Server: ${server}`);

    // ── Cookies (technology only, never a version) ─────────────────────────
    const cookieNames = base.setCookies.map((c) => c.split('=')[0].trim());
    const cookieHints: Array<[RegExp, string, string]> = [
      [/^PHPSESSID$/, 'PHP', 'Language'],
      [/^JSESSIONID$/, 'Java Servlet container', 'Application server'],
      [/^ASP\.NET_SessionId$|^\.AspNetCore\./, 'ASP.NET', 'Web framework'],
      [/^laravel_session$/, 'Laravel', 'Web framework'],
      [/^connect\.sid$/, 'Express', 'Web framework'],
      [/^csrftoken$/, 'Django', 'Web framework'],
      [/^wordpress_|^wp-settings/, 'WordPress', 'CMS'],
    ];
    for (const name of cookieNames) {
      for (const [re, tech, category] of cookieHints) if (re.test(name)) add(tech, category, null, 'medium', `Cookie name: ${name}`);
    }

    // ── HTML ───────────────────────────────────────────────────────────────
    const html = base.body || '';
    const generator = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)?.[1]
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i)?.[1];
    if (generator) {
      const gens: Array<[RegExp, string, string]> = [
        [/WordPress\s*([\d.]+)?/i, 'WordPress', 'CMS'],
        [/Drupal\s*([\d.]+)?/i, 'Drupal', 'CMS'],
        [/Joomla!?\s*([\d.]+)?/i, 'Joomla', 'CMS'],
        [/Hugo\s*([\d.]+)?/i, 'Hugo', 'Static site generator'],
        [/Ghost\s*([\d.]+)?/i, 'Ghost', 'CMS'],
        [/Jekyll\s*v?([\d.]+)?/i, 'Jekyll', 'Static site generator'],
        [/Wix\.com/i, 'Wix', 'Website builder'],
      ];
      for (const [re, name, category] of gens) {
        const m = generator.match(re);
        if (m) add(name, category, cleanVersion(m[1]), 'high', `<meta name="generator" content="${generator}">`);
      }
    }
    if (/\/wp-(content|includes)\//i.test(html)) add('WordPress', 'CMS', null, 'high', 'References to /wp-content/ or /wp-includes/');
    const ng = html.match(/ng-version=["']([\d.]+)["']/i);
    if (ng) add('Angular', 'JavaScript framework', cleanVersion(ng[1]), 'high', `ng-version="${ng[1]}"`);
    if (/id=["']__NEXT_DATA__["']/.test(html)) add('Next.js', 'Web framework', null, 'high', '__NEXT_DATA__ script element');
    if (/window\.__NUXT__/.test(html)) add('Nuxt', 'Web framework', null, 'high', 'window.__NUXT__');
    if (/data-reactroot|react-dom(\.production)?(\.min)?\.js/i.test(html)) add('React', 'JavaScript library', null, 'medium', 'React DOM markers');

    const scripts = [...html.matchAll(/<(?:script|link)\b[^>]+(?:src|href)=["']([^"']+)["']/gi)].map((m) => m[1]);
    const libs: Array<[RegExp, string, string]> = [
      [/jquery[-.]?(\d+\.\d+\.\d+)(?:\.slim)?(?:\.min)?\.js/i, 'jQuery', 'JavaScript library'],
      [/jquery@(\d+\.\d+\.\d+)/i, 'jQuery', 'JavaScript library'],
      [/\/jquery\/(\d+\.\d+\.\d+)\/jquery(?:\.min)?\.js/i, 'jQuery', 'JavaScript library'],
      [/jquery-ui[-.]?(\d+\.\d+\.\d+)/i, 'jQuery UI', 'JavaScript library'],
      [/bootstrap@(\d+\.\d+\.\d+)|\/bootstrap\/(\d+\.\d+\.\d+)\//i, 'Bootstrap', 'CSS framework'],
      [/angular(?:\.min)?\.js\/?(\d+\.\d+\.\d+)|angularjs\/(\d+\.\d+\.\d+)\//i, 'AngularJS', 'JavaScript framework'],
      [/vue@(\d+\.\d+\.\d+)|\/vue\/(\d+\.\d+\.\d+)\//i, 'Vue.js', 'JavaScript framework'],
      [/lodash@(\d+\.\d+\.\d+)|\/lodash\.js\/(\d+\.\d+\.\d+)\//i, 'Lodash', 'JavaScript library'],
      [/moment@(\d+\.\d+\.\d+)|\/moment\.js\/(\d+\.\d+\.\d+)\//i, 'Moment.js', 'JavaScript library'],
    ];
    for (const src of scripts) {
      for (const [re, name, category] of libs) {
        const m = src.match(re);
        if (m) add(name, category, cleanVersion(m[1] || m[2]), 'high', `Asset: ${src}`);
      }
      const wpVer = src.match(/\/wp-includes\/[^?]+\?ver=(\d+\.\d+(?:\.\d+)?)/i);
      if (wpVer) add('WordPress', 'CMS', cleanVersion(wpVer[1]), 'medium', `Asset version parameter: ${src}`);
    }

    ctx.data.technologies = [...found.values()];
    const versioned = ctx.data.technologies.filter((t) => t.version).length;
    return result([], `${ctx.data.technologies.length} technolog${ctx.data.technologies.length === 1 ? 'y' : 'ies'} identified (${versioned} with explicit version)`);
  },
};
