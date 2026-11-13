import axios from 'axios';
import { CheckDefinition, COMPREHENSIVE_ONLY, result, skipped, inconclusive } from '../context';
import { makeFinding, REF } from '../findings';
import { CveRecord, Finding, Severity, TechnologyInfo } from '../types';

/**
 * CVE correlation via the official NVD CVE API 2.0 (comprehensive profile).
 * https://nvd.nist.gov/developers/vulnerabilities
 *
 * Query: cpeName=<cpe with exact version>&isVulnerable — NVD evaluates the CVE
 * configurations (including versionStart/versionEnd ranges) and returns only
 * CVEs where that exact version is marked vulnerable.
 *
 * Rate limits (NVD): 5 requests / 30 s without a key, 50 / 30 s with NVD_API_KEY.
 * Results are cached in memory for 24 h. External availability is never
 * required for the rest of the scan.
 */

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CACHE_TTL_MS = 24 * 3600 * 1000;
const MAX_LISTED = 10;

interface CacheEntry {
  fetchedAt: number;
  total: number;
  records: CveRecord[];
}

const cache = new Map<string, CacheEntry>();
let nextSlot = 0;

const spacingMs = () => (process.env.NVD_API_KEY ? 700 : 6500);

/** Serialises NVD calls process-wide to respect the published rate limit. */
const waitForSlot = async (signal: AbortSignal) => {
  const now = Date.now();
  const at = Math.max(now, nextSlot);
  nextSlot = at + spacingMs();
  const delay = at - now;
  if (delay > 0) {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, delay);
      signal.addEventListener('abort', () => { clearTimeout(timer); reject(new Error('CANCELLED')); }, { once: true });
    });
  }
};

const severityFromCvss = (score: number | null): Severity => {
  if (score === null) return 'medium';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return score > 0 ? 'low' : 'info';
};

export const parseNvdResponse = (data: any): CacheEntry => {
  const records: CveRecord[] = (data?.vulnerabilities || []).map((item: any) => {
    const cve = item?.cve || {};
    const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV40?.[0] || cve.metrics?.cvssMetricV2?.[0];
    const cvss = metric?.cvssData?.baseScore ?? null;
    return {
      id: String(cve.id || ''),
      cvss: typeof cvss === 'number' ? cvss : null,
      cvssVersion: metric?.cvssData?.version ?? null,
      severity: metric?.cvssData?.baseSeverity || metric?.baseSeverity || null,
      description: String(cve.descriptions?.find((d: any) => d.lang === 'en')?.value || '').slice(0, 400),
      published: cve.published || null,
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    };
  }).filter((r: CveRecord) => r.id.startsWith('CVE-'));
  records.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
  return { fetchedAt: Date.now(), total: Number(data?.totalResults ?? records.length), records };
};

export const lookupCves = async (cpe: string, signal: AbortSignal): Promise<CacheEntry & { cached: boolean }> => {
  const hit = cache.get(cpe);
  if (hit && Date.now() - hit.fetchedAt < CACHE_TTL_MS) return { ...hit, cached: true };

  let lastError: unknown;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await waitForSlot(signal);
    try {
      // isVulnerable is a flag parameter (no value), so it is appended manually.
      const res = await axios.get(`${NVD_URL}?cpeName=${encodeURIComponent(cpe)}&isVulnerable&resultsPerPage=200`, {
        timeout: 30000,
        signal,
        maxContentLength: 20 * 1024 * 1024,
        headers: { 'User-Agent': 'RAKSHAK-VulnScanner/1.0', ...(process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}) },
      });
      const entry = parseNvdResponse(res.data);
      cache.set(cpe, entry);
      return { ...entry, cached: false };
    } catch (err: any) {
      if (signal.aborted) throw new Error('CANCELLED');
      lastError = err;
      if (err?.response && err.response.status < 500 && err.response.status !== 429) break; // not retryable
    }
  }
  throw lastError;
};

const describeError = (err: any) => (err?.response ? `HTTP ${err.response.status}` : err?.code || err?.message || 'unknown error');

export const cveCorrelationCheck: CheckDefinition = {
  id: 'cve-correlation',
  label: 'Known vulnerabilities (NVD CVE correlation)',
  phase: 'CVE Correlation',
  profiles: COMPREHENSIVE_ONLY,
  async run(ctx) {
    const candidates = ctx.data.technologies.filter((t): t is TechnologyInfo & { cpe: string } => Boolean(t.cpe));
    if (!candidates.length) {
      return skipped('No technology with an explicit version and a known CPE identifier was detected, so no CVE lookup was possible.');
    }
    const findings: Finding[] = [];
    const failures: string[] = [];
    const checkedAt = new Date().toISOString();

    for (const tech of candidates.slice(0, 5)) {
      try {
        const lookup = await lookupCves(tech.cpe, ctx.signal);
        if (!lookup.total) continue;
        const top = lookup.records.slice(0, MAX_LISTED);
        const maxCvss = top[0]?.cvss ?? null;
        findings.push(makeFinding({
          checkId: 'cve-correlation', key: tech.cpe,
          title: `${tech.name} ${tech.version}: ${lookup.total} known CVE${lookup.total === 1 ? '' : 's'} for this version`,
          category: 'Known Vulnerabilities (CVE)', owasp: 'A06:2021 Vulnerable and Outdated Components',
          severity: severityFromCvss(maxCvss),
          confidence: tech.confidence === 'high' ? 'medium' : 'low',
          verification: 'potential',
          description: `NVD lists ${lookup.total} CVE(s) whose affected-version ranges include ${tech.name} ${tech.version}. This is a version-based match: the detected version may be inaccurate, or fixes may have been backported (common in Linux distribution packages). Each CVE also requires specific modules or configurations, so exposure must be verified manually.`,
          affected: ctx.data.base?.url || ctx.target.url.href,
          evidence: [
            { label: 'Detected technology', value: `${tech.name} ${tech.version}` },
            { label: 'Version evidence', value: tech.evidence },
            { label: 'CPE queried', value: tech.cpe },
            { label: 'Highest CVSS', value: maxCvss !== null ? String(maxCvss) : 'n/a' },
            { label: 'Intelligence source', value: `NIST NVD CVE API 2.0${lookup.cached ? ' (cached)' : ''}` },
            { label: 'Checked at', value: checkedAt },
          ],
          detection: 'CPE built from explicit version evidence; NVD queried with cpeName + isVulnerable (version ranges evaluated by NVD).',
          impact: 'If the version is accurate and the affected component is enabled, attackers can use publicly documented exploits.',
          remediation: `Upgrade ${tech.name} to the latest supported release, then re-scan. If you rely on distribution packages, confirm the patch level with your vendor’s security advisories.`,
          references: [REF.nvd, REF.owaspA06],
          cveId: top[0]?.id,
          cves: top,
        }));
      } catch (err: any) {
        if (err?.message === 'CANCELLED' || ctx.signal.aborted) throw err;
        failures.push(`${tech.name}: ${describeError(err)}`);
      }
    }

    if (failures.length && !findings.length) return inconclusive(`NVD lookup failed (${failures.join('; ')}). Other results are unaffected.`);
    return result(findings, `${candidates.length} versioned technolog${candidates.length === 1 ? 'y' : 'ies'} checked against NVD${failures.length ? `; failed: ${failures.join('; ')}` : ''}`);
  },
};
