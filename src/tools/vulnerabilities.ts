/**
 * Vulnerability-related tools for the Nessus MCP server
 */

import { getVulnerabilityDetails, searchVulnerabilities } from '../nessus-api.js';
import {
  validateVulnerabilityId,
  handleNessusApiError
} from '../utils/error-handling.js';

/**
 * Tool to get vulnerability details
 */
export const getVulnerabilityDetailsToolSchema = {
  name: 'get_vulnerability_details',
  description:
    'Get detailed information about a specific vulnerability. In mock mode, pass a CVE id (e.g., CVE-2021-44228). ' +
    'Against a real Nessus instance, pass the numeric Nessus plugin ID instead (e.g., 156327) - Nessus has no API to ' +
    'resolve a CVE directly, so use search_vulnerabilities with a scan_id to find the plugin ID for a CVE first.',
  inputSchema: {
    type: 'object',
    properties: {
      vulnerability_id: {
        type: 'string',
        description: 'ID of the vulnerability: a CVE id in mock mode, or a numeric Nessus plugin ID against a real Nessus instance'
      }
    },
    required: ['vulnerability_id']
  },
  outputSchema: {
    type: 'object',
    properties: {
      error: { type: 'string' },
      id: { type: 'string' },
      plugin_id: { type: 'string' },
      name: { type: 'string' },
      family: { type: 'string' },
      severity: { type: 'string' },
      cvss_score: {},
      description: { type: 'string' },
      affected_systems: { type: 'array', items: { type: 'string' } },
      remediation: { type: 'string' },
      references: { type: 'array', items: { type: 'string' } }
    }
  },
  annotations: {
    title: 'Get Vulnerability Details',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true
  }
};

export const getVulnerabilityDetailsToolHandler = async (args: Record<string, unknown>) => {
  try {
    // Validate arguments
    const vulnId = validateVulnerabilityId(args.vulnerability_id);

    // Get vulnerability details
    const details = await getVulnerabilityDetails(vulnId);

    // Check if there was an error
    if ('error' in details) {
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${details.error}`
          }
        ],
        isError: true,
        structuredContent: details
      };
    }

    // Format the vulnerability details
    const formattedDetails = formatVulnerabilityDetails(details);

    return {
      content: [
        {
          type: 'text',
          text: formattedDetails
        }
      ],
      structuredContent: details
    };
  } catch (error) {
    const mcpError = handleNessusApiError(error);
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${mcpError.message}`
        }
      ],
      isError: true
    };
  }
};

/**
 * Format vulnerability details for better readability
 * @param details Vulnerability details to format
 */
const formatVulnerabilityDetails = (details: any): string => {
  if (!details) {
    return 'No vulnerability details available';
  }

  let formatted = `# ${details.name} (${details.id})\n\n`;

  // Add severity and CVSS score
  formatted += `**Severity:** ${details.severity?.toUpperCase() || 'Unknown'}\n`;
  formatted += `**CVSS Score:** ${details.cvss_score || 'N/A'}\n\n`;

  // Add description
  if (details.description) {
    formatted += `## Description\n\n${details.description}\n\n`;
  }

  // Add affected systems
  if (details.affected_systems && details.affected_systems.length > 0) {
    formatted += `## Affected Systems\n\n`;
    details.affected_systems.forEach((system: string) => {
      formatted += `- ${system}\n`;
    });
    formatted += '\n';
  }

  // Add remediation
  if (details.remediation) {
    formatted += `## Remediation\n\n${details.remediation}\n\n`;
  }

  // Add references
  if (details.references && details.references.length > 0) {
    formatted += `## References\n\n`;
    details.references.forEach((ref: string) => {
      formatted += `- ${ref}\n`;
    });
    formatted += '\n';
  }

  return formatted;
};

/**
 * Tool to search for vulnerabilities by keyword
 *
 * In mock mode this searches the static sample vulnerability list. Against
 * a real Nessus instance there is no single "search everything" endpoint
 * (see the design note above searchVulnerabilities in nessus-api.ts), so
 * this searches actual completed scans' plugin findings: a specific scan
 * when `scan_id` is given, otherwise the most recently updated completed
 * scans (bounded, so this stays reasonable on instances with many scans).
 */
export const searchVulnerabilitiesToolSchema = {
  name: 'search_vulnerabilities',
  description:
    'Search for vulnerabilities by keyword. In mock mode, searches the built-in sample data. Against a real Nessus ' +
    'instance, searches plugin findings from actual completed scans: pass scan_id to search one specific scan, or omit ' +
    'it to search the most recently updated completed scans (there is no global vulnerability search API on-prem).',
  inputSchema: {
    type: 'object',
    properties: {
      keyword: {
        type: 'string',
        description: 'Keyword to search for in vulnerability/plugin names (and descriptions, in mock mode)'
      },
      scan_id: {
        type: 'string',
        description:
          'Optional. Real mode only: restrict the search to this scan ID instead of scanning the most recent completed scans.'
      }
    },
    required: ['keyword']
  },
  outputSchema: {
    type: 'object',
    properties: {
      matches: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            plugin_id: {},
            name: { type: 'string' },
            severity: { type: 'string' },
            cvss_score: {},
            description: { type: 'string' },
            remediation: { type: 'string' },
            references: { type: 'array', items: { type: 'string' } },
            count: {},
            scan_id: { type: 'string' },
            scan_name: { type: 'string' },
            affected_systems: { type: 'array', items: { type: 'string' } }
          }
        }
      },
      scannedScans: {
        type: 'array',
        items: {
          type: 'object',
          properties: { id: { type: 'string' }, name: { type: 'string' } },
          required: ['id']
        }
      },
      truncated: { type: 'boolean' }
    },
    required: ['matches', 'scannedScans', 'truncated']
  },
  annotations: {
    title: 'Search Vulnerabilities',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true
  }
};

export const searchVulnerabilitiesToolHandler = async (args: Record<string, unknown>) => {
  try {
    // Validate arguments
    if (!args.keyword || typeof args.keyword !== 'string') {
      return {
        content: [
          {
            type: 'text',
            text: 'Error: Keyword is required and must be a string'
          }
        ],
        isError: true
      };
    }

    if (args.scan_id !== undefined && typeof args.scan_id !== 'string') {
      return {
        content: [
          {
            type: 'text',
            text: 'Error: scan_id must be a string when provided'
          }
        ],
        isError: true
      };
    }

    const keyword = args.keyword;
    const scanId = args.scan_id as string | undefined;

    const { matches, scannedScans, truncated } = await searchVulnerabilities(keyword, scanId);

    if (matches.length === 0) {
      const scope = scannedScans.length > 0 ? ` (searched ${scannedScans.length} scan(s): ${scannedScans.map((s) => s.name ?? s.id).join(', ')})` : '';
      return {
        content: [
          {
            type: 'text',
            text: `No vulnerabilities found matching "${keyword}"${scope}`
          }
        ],
        structuredContent: { matches, scannedScans, truncated }
      };
    }

    // Format the search results
    let results = `# Vulnerability Search Results for "${keyword}"\n\n`;
    results += `Found ${matches.length} matching vulnerabilities`;
    if (scannedScans.length > 0) {
      results += ` across ${scannedScans.length} scan(s): ${scannedScans.map((s) => s.name ?? s.id).join(', ')}`;
    }
    results += '.\n\n';
    if (truncated) {
      results += `Note: more completed scans exist than were searched; pass scan_id to target a specific one.\n\n`;
    }

    matches.forEach((vuln: any, index: number) => {
      results += `## ${index + 1}. ${vuln.name} (${vuln.id})\n\n`;
      results += `**Severity:** ${(vuln.severity || 'unknown').toString().toUpperCase()}\n`;
      results += `**CVSS Score:** ${vuln.cvss_score ?? 'N/A'}\n`;
      if (vuln.scan_name || vuln.scan_id) {
        results += `**Found in scan:** ${vuln.scan_name ?? vuln.scan_id}\n`;
      }
      results += '\n';
      if (vuln.description) {
        results += `${vuln.description}\n\n`;
      }
      const detailId = vuln.plugin_id ?? vuln.id;
      results += `To get full details, use the \`get_vulnerability_details\` tool with vulnerability_id: ${detailId}\n\n`;
    });

    return {
      content: [
        {
          type: 'text',
          text: results
        }
      ],
      structuredContent: { matches, scannedScans, truncated }
    };
  } catch (error) {
    const mcpError = handleNessusApiError(error);
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${mcpError.message}`
        }
      ],
      isError: true
    };
  }
};
