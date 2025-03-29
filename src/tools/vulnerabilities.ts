/**
 * Vulnerability-related tools for the Nessus MCP server
 */

import { getVulnerabilityDetails } from '../nessus-api.js';
import {
  validateVulnerabilityId,
  handleNessusApiError
} from '../utils/error-handling.js';

/**
 * Tool to get vulnerability details
 */
export const getVulnerabilityDetailsToolSchema = {
  name: 'get_vulnerability_details',
  description: 'Get detailed information about a specific vulnerability',
  inputSchema: {
    type: 'object',
    properties: {
      vulnerability_id: {
        type: 'string',
        description: 'ID of the vulnerability (e.g., CVE-2021-44228)'
      }
    },
    required: ['vulnerability_id']
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
        isError: true
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
 */
export const searchVulnerabilitiesToolSchema = {
  name: 'search_vulnerabilities',
  description: 'Search for vulnerabilities by keyword',
  inputSchema: {
    type: 'object',
    properties: {
      keyword: {
        type: 'string',
        description: 'Keyword to search for in vulnerability names and descriptions'
      }
    },
    required: ['keyword']
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

    const keyword = args.keyword.toLowerCase();

    // Import vulnerabilities from mock-data
    const { vulnerabilities } = await import('../mock-data.js');

    // Search for vulnerabilities matching the keyword
    const matches = vulnerabilities.filter(vuln =>
      vuln.name.toLowerCase().includes(keyword) ||
      vuln.description.toLowerCase().includes(keyword)
    );

    if (matches.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No vulnerabilities found matching "${args.keyword}"`
          }
        ]
      };
    }

    // Format the search results
    let results = `# Vulnerability Search Results for "${args.keyword}"\n\n`;
    results += `Found ${matches.length} matching vulnerabilities:\n\n`;

    matches.forEach((vuln, index) => {
      results += `## ${index + 1}. ${vuln.name} (${vuln.id})\n\n`;
      results += `**Severity:** ${vuln.severity.toUpperCase()}\n`;
      results += `**CVSS Score:** ${vuln.cvss_score}\n\n`;
      results += `${vuln.description}\n\n`;
      results += `To get full details, use the \`get_vulnerability_details\` tool with vulnerability_id: ${vuln.id}\n\n`;
    });

    return {
      content: [
        {
          type: 'text',
          text: results
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
