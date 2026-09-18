/**
 * Nessus API client
 *
 * Provides an interface to the Tenable Nessus REST API, with a fallback to
 * mock data for local development/testing when no credentials are configured.
 *
 * Real-mode requests authenticate using Nessus's API-key scheme: an
 * `X-ApiKeys: accessKey=<key>; secretKey=<key>` header on every request
 * (see https://developer.tenable.com/docs/authorization). There is no
 * separate login/session step needed for this auth method.
 */

import fetch, { type RequestInit as NodeFetchRequestInit } from 'node-fetch';
import http from 'node:http';
import https from 'node:https';

import {
  scanTemplates,
  createMockScan,
  getMockScanStatus,
  getMockScanResults,
  getMockVulnerabilityDetails,
  mockScans,
  vulnerabilities as mockVulnerabilities
} from './mock-data.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Configuration for Nessus API
interface NessusConfig {
  url?: string;
  accessKey?: string;
  secretKey?: string;
  useMock: boolean;
  /**
   * When true, TLS certificate verification is disabled for requests to
   * NESSUS_URL. Nessus instances very commonly run with a self-signed
   * certificate, so this is opt-in (via NESSUS_ALLOW_SELF_SIGNED=true) and
   * defaults to strict verification.
   */
  allowSelfSigned: boolean;
}

// Default configuration
const defaultConfig: NessusConfig = {
  useMock: true,
  allowSelfSigned: false
};

// Current configuration
let config: NessusConfig = { ...defaultConfig };

/**
 * Initialize the Nessus API client
 * @param newConfig Configuration options
 */
export const initializeNessusApi = (newConfig: Partial<NessusConfig> = {}) => {
  config = { ...defaultConfig, ...newConfig };

  // Check if we have API credentials
  if (config.url && config.accessKey && config.secretKey) {
    config.useMock = false;
    // NOTE: this server communicates with its MCP client over stdio, so all
    // logging must go to stderr (console.error), never stdout (console.log).
    console.error('Nessus API client initialized with real API credentials');
    if (config.allowSelfSigned) {
      console.error(
        'WARNING: NESSUS_ALLOW_SELF_SIGNED is enabled - TLS certificate verification is DISABLED for requests to NESSUS_URL. Only use this against a Nessus instance you trust.'
      );
    }
  } else {
    config.useMock = true;
    console.error('Nessus API client initialized in mock mode');
  }

  return config;
};

// ---------------------------------------------------------------------------
// Low-level HTTP client
// ---------------------------------------------------------------------------

const REQUEST_TIMEOUT_MS = 30_000;

// Agents are created lazily and reused across requests (keep-alive friendly).
const keepAliveHttpAgent = new http.Agent({ keepAlive: true });
const strictHttpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: true });
let insecureHttpsAgent: https.Agent | undefined;

const getInsecureHttpsAgent = (): https.Agent => {
  if (!insecureHttpsAgent) {
    insecureHttpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });
  }
  return insecureHttpsAgent;
};

/**
 * Picks the right Node agent for a request URL, honoring NESSUS_ALLOW_SELF_SIGNED.
 */
const selectAgent = (parsedUrl: URL) => {
  if (parsedUrl.protocol === 'http:') {
    return keepAliveHttpAgent;
  }
  return config.allowSelfSigned ? getInsecureHttpsAgent() : strictHttpsAgent;
};

interface NessusRequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
}

/**
 * Build the full request URL for a Nessus API path, applying NESSUS_URL as
 * the base and appending any query parameters.
 */
const buildUrl = (path: string, query?: NessusRequestOptions['query']): URL => {
  if (!config.url) {
    throw new Error(
      'Nessus API is not configured: NESSUS_URL is missing. Set NESSUS_URL, NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY, or omit them all to run in mock mode.'
    );
  }

  const base = config.url.replace(/\/+$/, '');
  const url = new URL(`${base}${path.startsWith('/') ? path : `/${path}`}`);

  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined) {
        url.searchParams.set(key, String(value));
      }
    }
  }

  return url;
};

/**
 * Low-level authenticated request against the Nessus REST API.
 *
 * Throws on any failure (network/TLS/timeout, non-2xx HTTP status, or
 * missing configuration) with a descriptive message. Callers should let
 * these propagate up to handleNessusApiError, which maps them to a clean
 * MCP error response instead of crashing the process.
 */
const nessusRequest = async <T = unknown>(path: string, options: NessusRequestOptions = {}): Promise<T> => {
  const { method = 'GET', body, query } = options;

  if (!config.accessKey || !config.secretKey) {
    throw new Error(
      'Nessus API is not configured: NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY are missing. Set them, or omit all NESSUS_* variables to run in mock mode.'
    );
  }

  const url = buildUrl(path, query);

  const headers: Record<string, string> = {
    'X-ApiKeys': `accessKey=${config.accessKey}; secretKey=${config.secretKey}`,
    Accept: 'application/json'
  };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      agent: selectAgent,
      signal: controller.signal as NodeFetchRequestInit['signal']
    });
  } catch (err) {
    // node-fetch's own error message can be uninformative (e.g. an empty
    // "reason: " for some ECONNREFUSED cases), so surface the underlying
    // system error code (ECONNREFUSED, ENOTFOUND, CERT_HAS_EXPIRED, etc.)
    // whenever it's available and not already part of the message.
    const message = err instanceof Error ? err.message : String(err);
    const code = (err as { code?: string })?.code;
    const reason = code && !message.includes(code) ? `${message} [${code}]` : message;
    const abortHint = controller.signal.aborted ? ` (timed out after ${REQUEST_TIMEOUT_MS}ms)` : '';
    throw new Error(`Failed to reach Nessus API at ${url.origin}: ${reason}${abortHint}`);
  } finally {
    clearTimeout(timeout);
  }

  const rawText = await response.text();
  let payload: unknown;
  if (rawText) {
    try {
      payload = JSON.parse(rawText);
    } catch {
      payload = rawText;
    }
  }

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new Error(
        `Nessus API authentication failed (HTTP ${response.status}) for ${method} ${path}. Check NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY and that the key has permission for this action.`
      );
    }
    if (response.status === 404) {
      throw new Error(`Requested Nessus resource not found (HTTP 404) for ${method} ${path}.`);
    }

    const detail =
      payload && typeof payload === 'object' && payload !== null && 'error' in (payload as Record<string, unknown>)
        ? String((payload as Record<string, unknown>).error)
        : typeof payload === 'string' && payload
          ? payload
          : response.statusText;

    throw new Error(`Nessus API request failed (HTTP ${response.status}) for ${method} ${path}: ${detail}`);
  }

  return payload as T;
};

// ---------------------------------------------------------------------------
// Normalization helpers (real API -> this server's response shapes)
// ---------------------------------------------------------------------------

const SEVERITY_LABELS = ['info', 'low', 'medium', 'high', 'critical'] as const;
type SeverityLabel = (typeof SEVERITY_LABELS)[number];

const severityLabelFromIndex = (index: unknown): SeverityLabel => {
  const i = typeof index === 'number' ? index : Number(index);
  return SEVERITY_LABELS[i] ?? 'info';
};

const severityFromRiskFactor = (riskFactor: unknown, cvssScore: number | null): SeverityLabel => {
  const rf = typeof riskFactor === 'string' ? riskFactor.toLowerCase() : '';
  if (rf === 'critical') return 'critical';
  if (rf === 'high') return 'high';
  if (rf === 'medium') return 'medium';
  if (rf === 'low') return 'low';
  if (rf === 'none') return 'info';

  if (cvssScore !== null && !Number.isNaN(cvssScore)) {
    if (cvssScore >= 9) return 'critical';
    if (cvssScore >= 7) return 'high';
    if (cvssScore >= 4) return 'medium';
    if (cvssScore > 0) return 'low';
  }

  return 'info';
};

const toArray = (value: unknown): string[] => {
  if (Array.isArray(value)) return value.map(String);
  if (value === undefined || value === null || value === '') return [];
  return [String(value)];
};

/**
 * Normalizes a `GET /plugins/plugin/{id}` response into this server's
 * vulnerability-details shape (see mock-data.ts's vulnerability objects for
 * the target shape that tools/vulnerabilities.ts formats).
 */
const normalizePluginDetails = (pluginId: string, data: any) => {
  const attrs = data?.attributes ?? {};

  const cvss3 = Number.parseFloat(attrs.cvss3_base_score);
  const cvss2 = Number.parseFloat(attrs.cvss_base_score);
  const cvssScore = !Number.isNaN(cvss3) ? cvss3 : !Number.isNaN(cvss2) ? cvss2 : null;

  const references = [...toArray(attrs.see_also), ...toArray(attrs.cve).map((cve) => `https://nvd.nist.gov/vuln/detail/${cve}`)];

  return {
    id: pluginId,
    plugin_id: pluginId,
    name: data?.name ?? attrs.plugin_name ?? `Nessus Plugin ${pluginId}`,
    family: data?.family_name,
    severity: severityFromRiskFactor(attrs.risk_factor, cvssScore),
    cvss_score: cvssScore,
    description: attrs.description ?? attrs.synopsis ?? '',
    affected_systems: [] as string[],
    remediation: attrs.solution ?? '',
    references
  };
};

// Candidate real Nessus editor template `name` values for each logical scan
// type this server exposes. Nessus ships different built-in templates
// depending on version/licensing, so we try several known names and fall
// back to a fuzzy title match; see resolveTemplateUuid().
const TEMPLATE_NAME_CANDIDATES: Record<string, string[]> = {
  'basic-network-scan': ['basic', 'discovery'],
  'web-app-scan': ['webapp', 'web_app', 'scan_webapp'],
  'compliance-scan': ['pci_asv', 'policy_compliance', 'offline_config_audit', 'pci_quarterly_external', 'audit_cloud_infra']
};

const fetchRealScanTemplates = async (): Promise<any[]> => {
  const data = await nessusRequest<{ templates?: any[] }>('/editor/scan/templates');
  return Array.isArray(data?.templates) ? data.templates : [];
};

/**
 * Maps our logical scan_type ('basic-network-scan' | 'web-app-scan' |
 * 'compliance-scan') onto an actual scan template UUID from this Nessus
 * instance's editor. See TEMPLATE_NAME_CANDIDATES for the design rationale.
 */
const resolveTemplateUuid = async (scanType: string): Promise<{ uuid: string; matchedName: string }> => {
  const templates = await fetchRealScanTemplates();
  const candidates = TEMPLATE_NAME_CANDIDATES[scanType] ?? [];

  for (const candidateName of candidates) {
    const match = templates.find((t) => typeof t.name === 'string' && t.name.toLowerCase() === candidateName.toLowerCase());
    if (match?.uuid) {
      return { uuid: match.uuid, matchedName: match.name };
    }
  }

  // Fuzzy fallback: match every hyphen-separated keyword in scan_type
  // against the template's name/title (e.g. "web-app-scan" -> ["web","app","scan"]).
  const keywords = scanType.split('-').filter(Boolean);
  const fuzzy = templates.find((t) => {
    const haystack = `${t.name ?? ''} ${t.title ?? ''}`.toLowerCase();
    return keywords.every((k) => haystack.includes(k));
  });
  if (fuzzy?.uuid) {
    return { uuid: fuzzy.uuid, matchedName: fuzzy.name };
  }

  throw new Error(
    `No Nessus scan template matched scan_type "${scanType}" among ${templates.length} templates returned by this Nessus instance ` +
      `(tried names: ${candidates.join(', ') || '(none)'}). Use the list_scan_templates tool to see what is actually available, ` +
      'and adjust TEMPLATE_NAME_CANDIDATES in src/nessus-api.ts if this instance uses different template names.'
  );
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Get available scan templates
 */
export const getScanTemplates = async () => {
  if (config.useMock) {
    return { templates: scanTemplates };
  }

  const templates = await fetchRealScanTemplates();
  return {
    templates: templates.map((t) => ({
      id: t.uuid,
      name: t.name,
      title: t.title ?? t.name,
      description: t.desc ?? t.description ?? ''
    }))
  };
};

/**
 * Start a new scan
 * @param target Target IP or hostname
 * @param scanType Type of scan to run
 */
export const startScan = async (target: string, scanType: string) => {
  if (config.useMock) {
    const scanId = createMockScan(target, scanType);
    return {
      scan_id: scanId,
      status: 'queued',
      message: 'Scan queued successfully'
    };
  }

  const { uuid, matchedName } = await resolveTemplateUuid(scanType);

  const created = await nessusRequest<{ scan?: { id?: number | string } }>('/scans', {
    method: 'POST',
    body: {
      uuid,
      settings: {
        name: `${scanType} - ${target} - ${new Date().toISOString()}`,
        text_targets: target,
        enabled: true
      }
    }
  });

  const scanId = created?.scan?.id;
  if (scanId === undefined || scanId === null) {
    throw new Error('Nessus accepted the scan creation request but did not return a scan id in its response.');
  }

  try {
    await nessusRequest(`/scans/${scanId}/launch`, { method: 'POST' });
  } catch (launchError) {
    const reason = launchError instanceof Error ? launchError.message : String(launchError);
    throw new Error(`Scan ${scanId} was created (template "${matchedName}") but could not be launched: ${reason}`);
  }

  return {
    scan_id: String(scanId),
    status: 'queued',
    message: `Scan created and launched successfully using template "${matchedName}"`
  };
};

/**
 * Get scan status
 * @param scanId ID of the scan
 */
export const getScanStatus = async (scanId: string) => {
  if (config.useMock) {
    return getMockScanStatus(scanId);
  }

  const data = await nessusRequest<any>(`/scans/${encodeURIComponent(scanId)}`);
  const info = data?.info ?? {};

  return {
    id: scanId,
    status: info.status ?? 'unknown',
    target: info.targets,
    name: info.name,
    created:
      typeof info.scan_start === 'number' ? new Date(info.scan_start * 1000).toISOString() : (info.creation_date ?? undefined)
  };
};

/**
 * Get scan results
 * @param scanId ID of the scan
 */
export const getScanResults = async (scanId: string) => {
  if (config.useMock) {
    return getMockScanResults(scanId);
  }

  const data = await nessusRequest<any>(`/scans/${encodeURIComponent(scanId)}`);
  const info = data?.info ?? {};
  const status = info.status ?? 'unknown';

  if (status !== 'completed') {
    return {
      error: 'Scan results not available',
      status
    };
  }

  const hosts = Array.isArray(data.hosts) ? data.hosts : [];
  // GET /scans/{id} returns a `vulnerabilities` array that is a per-plugin
  // summary aggregated across the whole scan (plugin_id, plugin_name,
  // plugin_family, severity, count) - it is NOT per-host. Fetching full
  // description/CVSS/remediation for every plugin here would mean one extra
  // Nessus API call per finding, which does not scale for large scans, so
  // this summary is returned as-is and callers can drill into any one
  // finding with get_vulnerability_details(plugin_id).
  const pluginSummaries: any[] = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];

  const vulnerabilities = pluginSummaries.map((v: any) => ({
    id: `plugin-${v.plugin_id}`,
    plugin_id: v.plugin_id,
    name: v.plugin_name,
    severity: severityLabelFromIndex(v.severity),
    cvss_score: null as number | null,
    count: v.count,
    plugin_family: v.plugin_family,
    description: '',
    affected_systems: [] as string[],
    remediation: '',
    references: [] as string[]
  }));

  const summary = {
    total_hosts: hosts.length,
    total_vulnerabilities: vulnerabilities.length,
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length,
    info: vulnerabilities.filter((v) => v.severity === 'info').length
  };

  return {
    scan_id: scanId,
    scan_type: info.policy ?? info.name,
    target: info.targets,
    start_time: typeof info.scan_start === 'number' ? new Date(info.scan_start * 1000).toISOString() : undefined,
    end_time: typeof info.scan_end === 'number' ? new Date(info.scan_end * 1000).toISOString() : undefined,
    status,
    summary,
    vulnerabilities
  };
};

/**
 * List all scans
 */
export const listScans = async () => {
  if (config.useMock) {
    const scans = Array.from(mockScans.values()).map((scan: any) => ({
      id: scan.id,
      target: scan.target,
      type: scan.type,
      status: scan.status,
      created: scan.created
    }));

    return { scans };
  }

  const data = await nessusRequest<{ scans?: any[] | null }>('/scans');
  // Nessus returns `scans: null` (not []) when there are no scans at all.
  const scans = (data?.scans ?? []).map((s: any) => ({
    id: String(s.id),
    // The list endpoint does not include scan targets (only the detail
    // endpoint does), so `name` is the closest identifying field available
    // without an extra GET /scans/{id} call per scan.
    name: s.name,
    status: s.status,
    created: typeof s.creation_date === 'number' ? new Date(s.creation_date * 1000).toISOString() : undefined
  }));

  return { scans };
};

/**
 * Get vulnerability details
 * @param vulnId Vulnerability ID. In mock mode this is a CVE id (e.g.
 * "CVE-2021-44228"). In real mode this must be the numeric Nessus plugin
 * ID (e.g. "156327") - see the design note on searchVulnerabilities below
 * for why the on-prem Nessus REST API cannot resolve an arbitrary CVE or
 * keyword directly.
 */
export const getVulnerabilityDetails = async (vulnId: string) => {
  if (config.useMock) {
    return getMockVulnerabilityDetails(vulnId);
  }

  if (!/^\d+$/.test(vulnId)) {
    throw new Error(
      `Cannot look up "${vulnId}" against a live Nessus instance: the on-prem Nessus REST API has no endpoint to resolve a CVE or ` +
        'free-text ID directly to a plugin. Pass the numeric Nessus plugin ID instead (see the "plugin_id" field in get_scan_results ' +
        'or search_vulnerabilities output), or run search_vulnerabilities with a scan_id to find the plugin ID for a given CVE within that scan.'
    );
  }

  const data = await nessusRequest<any>(`/plugins/plugin/${vulnId}`);
  return normalizePluginDetails(vulnId, data);
};

// ---------------------------------------------------------------------------
// search_vulnerabilities support
//
// Design decision: the on-prem Nessus REST API has no single "search all
// vulnerabilities" endpoint - vulnerability data only exists in the context
// of a scan's results (GET /scans/{id}) or the static plugin database
// (GET /plugins/plugin/{id}, which is looked up by numeric ID, not keyword).
// So in real mode this searches plugin findings from actual completed
// scans: if `scanId` is given it scopes the search to that one scan;
// otherwise it searches the most recently-modified completed scans (capped
// at MAX_SCANS_TO_SEARCH, to bound API calls on instances with many scans).
// This is documented on the tool schema/README rather than being a silent
// limitation.
// ---------------------------------------------------------------------------

const MAX_SCANS_TO_SEARCH = 10;
const MAX_PLUGIN_DETAIL_LOOKUPS = 25;

export interface VulnerabilitySearchResult {
  matches: any[];
  scannedScans: { id: string; name?: string }[];
  truncated: boolean;
}

export const searchVulnerabilities = async (keyword: string, scanId?: string): Promise<VulnerabilitySearchResult> => {
  const term = keyword.toLowerCase();

  if (config.useMock) {
    const matches = mockVulnerabilities.filter(
      (v) => v.name.toLowerCase().includes(term) || v.description.toLowerCase().includes(term)
    );
    return { matches, scannedScans: [], truncated: false };
  }

  let scanIds: string[];
  let truncated = false;

  if (scanId) {
    scanIds = [scanId];
  } else {
    const scanList = await nessusRequest<{ scans?: any[] | null }>('/scans');
    const completed = (scanList?.scans ?? [])
      .filter((s: any) => s.status === 'completed')
      .sort((a: any, b: any) => (b.last_modification_date ?? 0) - (a.last_modification_date ?? 0));
    truncated = completed.length > MAX_SCANS_TO_SEARCH;
    scanIds = completed.slice(0, MAX_SCANS_TO_SEARCH).map((s: any) => String(s.id));
  }

  const scannedScans: { id: string; name?: string }[] = [];
  const rawMatches: any[] = [];

  for (const id of scanIds) {
    let detail: any;
    try {
      detail = await nessusRequest<any>(`/scans/${encodeURIComponent(id)}`);
    } catch {
      // A scan may have been deleted, or be inaccessible to this API key;
      // skip it rather than failing the whole search.
      continue;
    }

    const scanName = detail?.info?.name;
    scannedScans.push({ id, name: scanName });

    const pluginSummaries = Array.isArray(detail?.vulnerabilities) ? detail.vulnerabilities : [];
    for (const v of pluginSummaries) {
      const haystack = `${v.plugin_name ?? ''} ${v.plugin_family ?? ''}`.toLowerCase();
      if (haystack.includes(term)) {
        rawMatches.push({ ...v, scan_id: id, scan_name: scanName });
      }
    }
  }

  // Enrich a bounded number of unique plugins with full detail (CVSS,
  // description, remediation) via the plugin database, to keep this
  // reasonably informative without an unbounded number of extra requests.
  const detailCache = new Map<number, ReturnType<typeof normalizePluginDetails> | null>();
  const matches = [];

  for (const m of rawMatches) {
    if (!detailCache.has(m.plugin_id) && detailCache.size < MAX_PLUGIN_DETAIL_LOOKUPS) {
      try {
        const raw = await nessusRequest<any>(`/plugins/plugin/${m.plugin_id}`);
        detailCache.set(m.plugin_id, normalizePluginDetails(String(m.plugin_id), raw));
      } catch {
        detailCache.set(m.plugin_id, null);
      }
    }
    const detail = detailCache.get(m.plugin_id);

    matches.push({
      id: `plugin-${m.plugin_id}`,
      plugin_id: m.plugin_id,
      name: m.plugin_name,
      severity: severityLabelFromIndex(m.severity),
      cvss_score: detail?.cvss_score ?? null,
      description: detail?.description ?? '',
      remediation: detail?.remediation ?? '',
      references: detail?.references ?? [],
      count: m.count,
      scan_id: m.scan_id,
      scan_name: m.scan_name
    });
  }

  return { matches, scannedScans, truncated };
};

/**
 * Check if the Nessus API is available
 */
export const checkApiStatus = async () => {
  if (config.useMock) {
    return {
      status: 'ok',
      mode: 'mock',
      message: 'Using mock Nessus API'
    };
  }

  try {
    await nessusRequest('/scans');
    return {
      status: 'ok',
      mode: 'real',
      message: 'Connected to Nessus API'
    };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      status: 'error',
      mode: 'real',
      message: `Failed to connect to Nessus API: ${reason}`
    };
  }
};
