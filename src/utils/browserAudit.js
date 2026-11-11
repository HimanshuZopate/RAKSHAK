/**
 * browserAudit.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Client-side telemetry collector for the Security Audit feature.
 * All functions are non-destructive and read-only — they extract environment
 * info without modifying any browser state.
 */

// ─── Browser & OS Detection ────────────────────────────────────────────────────

const OUTDATED_VERSIONS = {
  Chrome: 110,
  Firefox: 100,
  Safari: 15,
  Edge: 100,
  Opera: 85,
  'Internet Explorer': 0, // Always outdated
};

/**
 * Parses navigator.userAgent to extract OS, Browser name, and version.
 * Returns an isOutdated flag if the version is below a known safe threshold.
 */
export function getBrowserInfo() {
  const ua = navigator.userAgent;

  // --- OS Detection ---
  let os = 'Unknown OS';
  if (/Windows NT 10/.test(ua))                os = 'Windows 10/11';
  else if (/Windows NT 6\.3/.test(ua))         os = 'Windows 8.1';
  else if (/Windows NT 6\.1/.test(ua))         os = 'Windows 7 (EOL)';
  else if (/Windows/.test(ua))                 os = 'Windows (Unknown Version)';
  else if (/Mac OS X/.test(ua)) {
    const macVer = ua.match(/Mac OS X ([\d_]+)/);
    os = macVer ? `macOS ${macVer[1].replace(/_/g, '.')}` : 'macOS';
  }
  else if (/Android/.test(ua)) {
    const av = ua.match(/Android ([\d.]+)/);
    os = av ? `Android ${av[1]}` : 'Android';
  }
  else if (/iPhone|iPad|iPod/.test(ua)) {
    const iosVer = ua.match(/OS ([\d_]+)/);
    os = iosVer ? `iOS ${iosVer[1].replace(/_/g, '.')}` : 'iOS';
  }
  else if (/Linux/.test(ua))                   os = 'Linux';

  // --- Browser Detection (order matters — Edge/OPR before Chrome) ---
  let browser = 'Unknown Browser';
  let version = 'Unknown';
  let versionNum = 0;

  const matchBrowser = (pattern, name) => {
    const m = ua.match(pattern);
    if (m) {
      browser = name;
      version = m[1];
      versionNum = parseFloat(m[1]);
      return true;
    }
    return false;
  };

  if (!matchBrowser(/Edg\/([\d.]+)/, 'Edge'))
  if (!matchBrowser(/OPR\/([\d.]+)/, 'Opera'))
  if (!matchBrowser(/SamsungBrowser\/([\d.]+)/, 'Samsung Browser'))
  if (!matchBrowser(/Firefox\/([\d.]+)/, 'Firefox'))
  if (!matchBrowser(/Chrome\/([\d.]+)/, 'Chrome'))
  if (!matchBrowser(/Version\/([\d.]+).*Safari/, 'Safari'))
  matchBrowser(/MSIE ([\d.]+)|Trident.*rv:([\d.]+)/, 'Internet Explorer');

  // --- Outdated Check ---
  const outdatedThreshold = OUTDATED_VERSIONS[browser] ?? null;
  const isOutdated =
    browser === 'Internet Explorer' ||
    os.includes('Windows 7') ||
    (outdatedThreshold !== null && versionNum < outdatedThreshold);

  return { os, browser, browserVersion: version, isOutdated };
}

// ─── Privacy Leak: WebRTC STUN ─────────────────────────────────────────────────

/**
 * Uses WebRTC's ICE candidate gathering to detect if the browser leaks the
 * user's local/internal IP address. This works even behind a NAT.
 *
 * Returns the leaked local IP string, or null if no leak detected / not supported.
 * Resolves within 2500ms (timeout).
 */
export function detectWebRtcLeak() {
  return new Promise((resolve) => {
    if (typeof RTCPeerConnection === 'undefined') {
      resolve(null);
      return;
    }

    let pc = null;
    const timeout = setTimeout(() => {
      cleanup();
      resolve(null);
    }, 2500);

    const cleanup = () => {
      clearTimeout(timeout);
      if (pc) {
        try { pc.close(); } catch {}
        pc = null;
      }
    };

    try {
      // Use a public STUN server — this never sends our data anywhere sensitive
      pc = new RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
      });

      // Create a dummy data channel to trigger ICE gathering
      pc.createDataChannel('');

      pc.createOffer()
        .then(offer => pc && pc.setLocalDescription(offer))
        .catch(() => { cleanup(); resolve(null); });

      let resolved = false;
      pc.onicecandidate = (e) => {
        if (!e.candidate || resolved) return;

        // Extract IP from the SDP candidate line
        const ipRegex = /(\d{1,3}(\.\d{1,3}){3})/;
        const match = e.candidate.candidate.match(ipRegex);

        if (match) {
          const ip = match[1];
          // Filter out: loopback (127.x), link-local (169.254.x), broadcast/gateway
          const isPrivate =
            ip.startsWith('10.') ||
            ip.startsWith('192.168.') ||
            /^172\.(1[6-9]|2\d|3[01])\./.test(ip);

          if (isPrivate && !ip.startsWith('0.')) {
            resolved = true;
            cleanup();
            resolve(ip);
          }
        }
      };

      pc.onicegatheringstatechange = () => {
        if (pc && pc.iceGatheringState === 'complete' && !resolved) {
          cleanup();
          resolve(null);
        }
      };
    } catch {
      cleanup();
      resolve(null);
    }
  });
}

// ─── Fingerprinting Vectors ────────────────────────────────────────────────────

/**
 * Returns the WebGL renderer string — a powerful fingerprinting vector
 * that can uniquely identify a GPU model. Strings like "Intel Iris" or
 * "NVIDIA GeForce RTX" are highly specific.
 */
export function getWebGLRenderer() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'WebGL not supported';

    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (ext) {
      const renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
      return renderer || 'Unknown Renderer';
    }
    return gl.getParameter(gl.RENDERER) || 'Unknown Renderer';
  } catch {
    return 'WebGL access denied';
  }
}

/**
 * Calculates a 0–100 "fingerprint score" representing how uniquely trackable
 * the browser is. Higher = more trackable.
 *
 * Factors:
 * - Uncommon screen resolutions (+20)
 * - Unusual timezone (+20)
 * - Specific WebGL renderer (not a generic string) (+25)
 * - Touch events support (+10)
 * - Language uniqueness (+10)
 * - Color depth not standard (+15)
 */
export function calculateFingerprintScore() {
  let score = 40; // baseline

  const { width, height, colorDepth } = window.screen;

  // Screen resolution entropy
  const commonResolutions = ['1920x1080', '1366x768', '1280x720', '1440x900', '2560x1440'];
  const res = `${width}x${height}`;
  if (!commonResolutions.includes(res)) score += 20;

  // Color depth
  if (colorDepth !== 24 && colorDepth !== 32) score += 15;

  // Timezone entropy
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const commonTimezones = ['America/New_York', 'America/Los_Angeles', 'Europe/London', 'Asia/Tokyo', 'UTC'];
  if (!commonTimezones.includes(tz)) score += 15;

  // WebGL renderer specificity
  const renderer = getWebGLRenderer();
  if (renderer !== 'WebGL not supported' && renderer !== 'Unknown Renderer') {
    if (renderer.toLowerCase().includes('nvidia') || renderer.toLowerCase().includes('amd') || renderer.toLowerCase().includes('intel')) {
      score += 20;
    } else {
      score += 10;
    }
  }

  // Touch/pointer support
  if (navigator.maxTouchPoints > 0) score += 5;

  // Non-English language
  if (!navigator.language?.startsWith('en')) score += 5;

  return Math.min(100, score);
}

// ─── Connection Security ───────────────────────────────────────────────────────

/**
 * Checks whether the current connection is over HTTPS.
 */
export function getConnectionSecurity() {
  const protocol = window.location.protocol;
  const isHttps = protocol === 'https:';
  return { protocol, isHttps };
}

// ─── Master Telemetry Collector ────────────────────────────────────────────────

/**
 * Gathers all client-side telemetry concurrently.
 * Returns a BrowserTelemetry object ready to be sent to the backend.
 */
export async function collectTelemetry() {
  const [webrtcLeakedIp] = await Promise.all([
    detectWebRtcLeak(),
  ]);

  const { os, browser, browserVersion, isOutdated } = getBrowserInfo();
  const { protocol, isHttps } = getConnectionSecurity();
  const webglRenderer = getWebGLRenderer();
  const fingerprintScore = calculateFingerprintScore();

  const screenResolution = `${window.screen.width}x${window.screen.height}`;
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  return {
    os,
    browser,
    browserVersion,
    isOutdated,
    protocol,
    isHttps,
    webrtcLeakedIp,
    screenResolution,
    timezone,
    webglRenderer,
    fingerprintScore,
  };
}
