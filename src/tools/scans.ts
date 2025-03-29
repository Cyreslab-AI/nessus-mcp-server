/**
 * Scan-related tools for the Nessus MCP server
 */

import { z } from 'zod';
import {
  getScanTemplates,
  startScan,
  getScanStatus,
  getScanResults,
  listScans
} from '../nessus-api.js';
import {
  validateScanId,
  validateTarget,
  validateScanType,
  handleNessusApiError
} from '../utils/error-handling.js';

/**
 * Tool to list available scan templates
 */
export const listScanTemplatesToolSchema = {
  name: 'list_scan_templates',
  description: 'List available Nessus scan templates',
  inputSchema: {
    type: 'object',
    properties: {}
  }
};

export const listScanTemplatesToolHandler = async () => {
  try {
    const templates = await getScanTemplates();
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(templates, null, 2)
        }
      ]
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
 * Tool to start a new scan
 */
export const startScanToolSchema = {
  name: 'start_scan',
  description: 'Start a new vulnerability scan against a target',
  inputSchema: {
    type: 'object',
    properties: {
      target: {
        type: 'string',
        description: 'Target IP address or hostname to scan'
      },
      scan_type: {
        type: 'string',
        description: 'Type of scan to run (basic-network-scan, web-app-scan, compliance-scan)'
      }
    },
    required: ['target', 'scan_type']
  }
};

export const startScanToolHandler = async (args: Record<string, unknown>) => {
  try {
    // Validate arguments
    const targetSchema = z.string().min(1);
    const scanTypeSchema = z.enum(['basic-network-scan', 'web-app-scan', 'compliance-scan']);

    const target = validateTarget(args.target);
    const scanType = validateScanType(args.scan_type);

    // Start the scan
    const result = await startScan(target, scanType);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2)
        }
      ]
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
 * Tool to get scan status
 */
export const getScanStatusToolSchema = {
  name: 'get_scan_status',
  description: 'Check the status of a running scan',
  inputSchema: {
    type: 'object',
    properties: {
      scan_id: {
        type: 'string',
        description: 'ID of the scan to check'
      }
    },
    required: ['scan_id']
  }
};

export const getScanStatusToolHandler = async (args: Record<string, unknown>) => {
  try {
    // Validate arguments
    const scanId = validateScanId(args.scan_id);

    // Get scan status
    const status = await getScanStatus(scanId);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(status, null, 2)
        }
      ]
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
 * Tool to get scan results
 */
export const getScanResultsToolSchema = {
  name: 'get_scan_results',
  description: 'Get the results of a completed scan',
  inputSchema: {
    type: 'object',
    properties: {
      scan_id: {
        type: 'string',
        description: 'ID of the scan to get results for'
      }
    },
    required: ['scan_id']
  }
};

export const getScanResultsToolHandler = async (args: Record<string, unknown>) => {
  try {
    // Validate arguments
    const scanId = validateScanId(args.scan_id);

    // Get scan results
    const results = await getScanResults(scanId);

    // Check if there was an error
    if ('error' in results) {
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${results.error}`
          }
        ],
        isError: true
      };
    }

    // Format the results
    const formattedResults = formatScanResults(results);

    return {
      content: [
        {
          type: 'text',
          text: formattedResults
        }
      ]
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
 * Tool to list all scans
 */
export const listScansToolSchema = {
  name: 'list_scans',
  description: 'List all scans and their status',
  inputSchema: {
    type: 'object',
    properties: {}
  }
};

export const listScansToolHandler = async () => {
  try {
    // Get all scans
    const scans = await listScans();

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(scans, null, 2)
        }
      ]
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
 * Format scan results for better readability
 * @param results Scan results to format
 */
const formatScanResults = (results: any): string => {
  if (!results || !results.vulnerabilities) {
    return JSON.stringify(results, null, 2);
  }

  // Create a summary section
  const summary = results.summary || {};
  let formattedResults = `# Scan Results for ${results.target || 'Unknown Target'}\n\n`;
  formattedResults += `Scan ID: ${results.scan_id || 'Unknown'}\n`;
  formattedResults += `Scan Type: ${results.scan_type || 'Unknown'}\n`;
  formattedResults += `Start Time: ${results.start_time || 'Unknown'}\n`;
  formattedResults += `End Time: ${results.end_time || 'Unknown'}\n`;
  formattedResults += `Status: ${results.status || 'Unknown'}\n\n`;

  // Add vulnerability summary
  formattedResults += `## Vulnerability Summary\n\n`;
  formattedResults += `Total Vulnerabilities: ${summary.total_vulnerabilities || 0}\n`;
  formattedResults += `Critical: ${summary.critical || 0}\n`;
  formattedResults += `High: ${summary.high || 0}\n`;
  formattedResults += `Medium: ${summary.medium || 0}\n`;
  formattedResults += `Low: ${summary.low || 0}\n`;
  formattedResults += `Info: ${summary.info || 0}\n\n`;

  // Add detailed vulnerability information
  formattedResults += `## Vulnerabilities\n\n`;

  // Sort vulnerabilities by severity
  const sortOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4 };
  const sortedVulns = [...results.vulnerabilities].sort((a, b) => {
    return (sortOrder[a.severity as keyof typeof sortOrder] || 999) -
           (sortOrder[b.severity as keyof typeof sortOrder] || 999);
  });

  // Format each vulnerability
  sortedVulns.forEach((vuln, index) => {
    formattedResults += `### ${index + 1}. ${vuln.name} (${vuln.id})\n\n`;
    formattedResults += `Severity: ${vuln.severity.toUpperCase()}\n`;
    formattedResults += `CVSS Score: ${vuln.cvss_score}\n\n`;
    formattedResults += `${vuln.description}\n\n`;

    if (vuln.affected_systems && vuln.affected_systems.length > 0) {
      formattedResults += `Affected Systems:\n`;
      vuln.affected_systems.forEach((system: string) => {
        formattedResults += `- ${system}\n`;
      });
      formattedResults += '\n';
    }

    if (vuln.remediation) {
      formattedResults += `Remediation: ${vuln.remediation}\n\n`;
    }

    if (vuln.references && vuln.references.length > 0) {
      formattedResults += `References:\n`;
      vuln.references.forEach((ref: string) => {
        formattedResults += `- ${ref}\n`;
      });
      formattedResults += '\n';
    }
  });

  return formattedResults;
};
