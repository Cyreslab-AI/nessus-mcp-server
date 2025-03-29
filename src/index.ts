#!/usr/bin/env node
/**
 * Nessus MCP Server
 *
 * This server provides an MCP interface to the Nessus vulnerability scanner.
 * It can operate in mock mode (default) or connect to a real Nessus API.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { initializeNessusApi } from './nessus-api.js';
import { handleNessusApiError } from './utils/error-handling.js';

// Import tool schemas and handlers
import {
  listScanTemplatesToolSchema,
  listScanTemplatesToolHandler,
  startScanToolSchema,
  startScanToolHandler,
  getScanStatusToolSchema,
  getScanStatusToolHandler,
  getScanResultsToolSchema,
  getScanResultsToolHandler,
  listScansToolSchema,
  listScansToolHandler
} from './tools/scans.js';

import {
  getVulnerabilityDetailsToolSchema,
  getVulnerabilityDetailsToolHandler,
  searchVulnerabilitiesToolSchema,
  searchVulnerabilitiesToolHandler
} from './tools/vulnerabilities.js';

// Initialize the Nessus API client
const initializeApi = () => {
  // Check for environment variables
  const nessusUrl = process.env.NESSUS_URL;
  const nessusAccessKey = process.env.NESSUS_ACCESS_KEY;
  const nessusSecretKey = process.env.NESSUS_SECRET_KEY;

  // Initialize the API client
  return initializeNessusApi({
    url: nessusUrl,
    accessKey: nessusAccessKey,
    secretKey: nessusSecretKey,
    useMock: !(nessusUrl && nessusAccessKey && nessusSecretKey)
  });
};

// Create and configure the MCP server
const createServer = () => {
  // Create the server instance
  const server = new Server(
    {
      name: 'nessus-server',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Register tools list handler
  server.setRequestHandler(
    ListToolsRequestSchema,
    async () => {
      return {
        tools: [
          listScanTemplatesToolSchema,
          startScanToolSchema,
          getScanStatusToolSchema,
          getScanResultsToolSchema,
          listScansToolSchema,
          getVulnerabilityDetailsToolSchema,
          searchVulnerabilitiesToolSchema
        ]
      };
    }
  );

  // Register tool call handler
  server.setRequestHandler(
    CallToolRequestSchema,
    async (request) => {
      try {
        const { name, arguments: args = {} } = request.params;

        // Route to the appropriate tool handler
        switch (name) {
          case 'list_scan_templates':
            return await listScanTemplatesToolHandler();
          case 'start_scan':
            return await startScanToolHandler(args);
          case 'get_scan_status':
            return await getScanStatusToolHandler(args);
          case 'get_scan_results':
            return await getScanResultsToolHandler(args);
          case 'list_scans':
            return await listScansToolHandler();
          case 'get_vulnerability_details':
            return await getVulnerabilityDetailsToolHandler(args);
          case 'search_vulnerabilities':
            return await searchVulnerabilitiesToolHandler(args);
          default:
            return {
              content: [
                {
                  type: 'text',
                  text: `Error: Unknown tool "${name}"`
                }
              ],
              isError: true
            };
        }
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
    }
  );

  return server;
};

// Main function
async function main() {
  try {
    // Initialize the API client
    const apiConfig = initializeApi();
    console.error(`Nessus MCP Server starting in ${apiConfig.useMock ? 'mock' : 'real API'} mode`);

    // Create the server
    const server = createServer();

    // Create the transport
    const transport = new StdioServerTransport();

    // Connect the server to the transport
    await server.connect(transport);

    console.error('Nessus MCP Server running on stdio');

    // Handle process termination
    process.on('SIGINT', async () => {
      console.error('Shutting down Nessus MCP Server...');
      await server.close();
      process.exit(0);
    });
  } catch (error) {
    console.error('Fatal error starting Nessus MCP Server:', error);
    process.exit(1);
  }
}

// Run the server
main().catch((error) => {
  console.error('Unhandled error in Nessus MCP Server:', error);
  process.exit(1);
});
