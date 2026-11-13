/**
 * RAKSHAK Vulnerability Scanner — controlled demonstration lab.
 *
 * Starts two deliberately configured websites bound to 127.0.0.1 only:
 *   http://127.0.0.1:4455  "Insecure Shop"  – many real (but harmless) weaknesses
 *   http://127.0.0.1:4456  "Hardened Shop"  – the same pages configured securely
 *
 * Nothing here is reachable from the network, and all "sensitive" files contain
 * dummy placeholder values only.
 *
 * Usage:   npm run vuln-lab
 * Scanner: set VULN_SCANNER_LAB_TARGETS=127.0.0.1:4455,127.0.0.1:4456 in .env and restart
 *          the backend (the scanner refuses loopback targets unless they are listed there).
 */
const http = require('http');

const page = (title, body) => `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title>
<meta name="generator" content="WordPress 5.0">
<script src="/js/jquery-1.12.4.min.js"></script>
</head><body><h1>${title}</h1>${body}</body></html>`;

const send = (res, status, headers, body = '') => {
  res.writeHead(status, headers);
  res.end(body);
};

// ── Insecure site ───────────────────────────────────────────────────────────
const insecure = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:4455');
  const origin = req.headers.origin;
  const base = {
    Server: 'Apache/2.4.49 (Unix) PHP/7.4.3',
    'X-Powered-By': 'PHP/7.4.3',
    'Content-Type': 'text/html; charset=utf-8',
    // CORS: reflects any Origin and allows credentials (deliberately vulnerable)
    ...(origin ? { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true' } : {}),
  };

  if (req.method === 'TRACE') {
    return send(res, 200, { ...base, 'Content-Type': 'message/http' }, `TRACE ${req.url} HTTP/1.1\r\nHost: ${req.headers.host}\r\n\r\n`);
  }
  if (req.method === 'OPTIONS') {
    return send(res, 200, { ...base, Allow: 'GET, POST, PUT, DELETE, TRACE, OPTIONS', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE' });
  }

  switch (url.pathname) {
    case '/':
      return send(res, 200, {
        ...base,
        'Set-Cookie': ['PHPSESSID=lab-session-value; Path=/', 'theme=dark; Path=/'],
        'X-Frame-Options': 'ALLOW-FROM https://example.com',
      }, page('Insecure Shop (RAKSHAK lab)', `
        <form method="post" action="http://127.0.0.1:4455/login">
          <input name="user"><input type="password" name="pass"><button>Sign in</button>
        </form>
        <p><a href="/search?q=shoes">Search</a> · <a href="/products?id=1">Product 1</a> · <a href="/login?next=/account">Account</a></p>`));
    case '/search': {
      const q = url.searchParams.get('q') || '';
      // Reflected without encoding (deliberately vulnerable)
      return send(res, 200, base, page('Search', `<p>Results for: ${q}</p>`));
    }
    case '/products': {
      const id = url.searchParams.get('id') || '1';
      // Simulates string concatenation into SQL: an unbalanced quote breaks the query.
      const quotes = (id.match(/'/g) || []).length;
      if (quotes % 2 === 1) {
        return send(res, 500, base, page('Error', `<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${id.replace(/</g, '&lt;')}' at line 1</p>`));
      }
      return send(res, 200, base, page('Product', `<p>Product #${id.replace(/[^0-9a-z']/gi, '')}</p>`));
    }
    case '/login': {
      const next = url.searchParams.get('next');
      if (next) return send(res, 302, { ...base, Location: next }); // open redirect (deliberately vulnerable)
      return send(res, 200, base, page('Login', '<p>Please sign in.</p>'));
    }
    case '/files/':
      return send(res, 200, base, '<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href="report.pdf">report.pdf</a></body></html>');
    case '/.env':
      return send(res, 200, { ...base, 'Content-Type': 'text/plain' }, 'APP_ENV=lab\nAPP_DEBUG=true\nDEMO_SETTING=placeholder-not-a-secret\n');
    case '/.git/HEAD':
      return send(res, 200, { ...base, 'Content-Type': 'text/plain' }, 'ref: refs/heads/main\n');
    // ── Edge cases for robustness testing ──
    case '/big': // 5 MB response: the scanner must stop reading at its size cap
      return send(res, 200, base, `<html><body>${'A'.repeat(5 * 1024 * 1024)}</body></html>`);
    case '/loop': // redirect loop
      return send(res, 302, { ...base, Location: '/loop' });
    case '/slow': // never responds: the scanner must time out
      return;
    case '/badgzip': // claims gzip but sends garbage (malformed response)
      return send(res, 200, { ...base, 'Content-Encoding': 'gzip' }, 'this is not gzip data');
    case '/js/jquery-1.12.4.min.js':
      return send(res, 200, { ...base, 'Content-Type': 'application/javascript' }, '/* placeholder for jQuery 1.12.4 */');
    default:
      return send(res, 404, base, '<b>Fatal error</b>: Uncaught Exception: Page not found in <b>/var/www/html/index.php</b> on line <b>42</b>');
  }
});

// ── Hardened site ───────────────────────────────────────────────────────────
const hardenedHeaders = {
  'Content-Type': 'text/html; charset=utf-8',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-site',
};
const hardened = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:4456');
  if (req.method === 'TRACE') return send(res, 405, hardenedHeaders, 'Method Not Allowed');
  if (req.method === 'OPTIONS') return send(res, 204, { ...hardenedHeaders, Allow: 'GET, HEAD, OPTIONS' });
  if (url.pathname === '/') {
    return send(res, 200, { ...hardenedHeaders, 'Set-Cookie': '__Host-session=lab-session-value; Path=/; Secure; HttpOnly; SameSite=Strict' },
      '<!doctype html><html><head><meta charset="utf-8"><title>Hardened Shop (RAKSHAK lab)</title></head><body><h1>Hardened Shop</h1><p>Search: <a href="/search?q=shoes">shoes</a></p></body></html>');
  }
  if (url.pathname === '/search') {
    const q = (url.searchParams.get('q') || '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`); // encoded output
    return send(res, 200, hardenedHeaders, `<!doctype html><html><head><title>Search</title></head><body><p>Results for: ${q}</p></body></html>`);
  }
  return send(res, 404, hardenedHeaders, '<!doctype html><html><head><title>Not found</title></head><body><p>Page not found.</p></body></html>');
});

insecure.listen(4455, '127.0.0.1', () => console.log('Insecure lab site: http://127.0.0.1:4455'));
hardened.listen(4456, '127.0.0.1', () => console.log('Hardened lab site: http://127.0.0.1:4456'));
