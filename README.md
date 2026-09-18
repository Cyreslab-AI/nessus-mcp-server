# Nessus MCP Server

A Model Context Protocol (MCP) server for interacting with the Tenable Nessus vulnerability scanner. This server allows AI assistants to perform vulnerability scanning and analysis through the MCP protocol.

It talks to a real Nessus instance over its REST API using API-key authentication. If no `NESSUS_URL`/`NESSUS_ACCESS_KEY`/`NESSUS_SECRET_KEY` are set, it falls back to a self-contained mock mode for local development and testing.

## Features

- **Vulnerability Scanning**: Start and monitor vulnerability scans against specified targets
- **Scan Management**: List, track, and retrieve results from vulnerability scans
- **Vulnerability Analysis**: Search for and get detailed information about specific vulnerabilities
- **Mock Mode**: Fully functional mock mode for testing without a Nessus API key

## Tools

The server provides the following tools:

| Tool Name                   | Description                                             |
| --------------------------- | ------------------------------------------------------- |
| `list_scan_templates`       | List available Nessus scan templates                    |
| `start_scan`                | Start a new vulnerability scan against a target         |
| `get_scan_status`           | Check the status of a running scan                      |
| `get_scan_results`          | Get the results of a completed scan                     |
| `list_scans`                | List all scans and their status                         |
| `get_vulnerability_details` | Get detailed information about a specific vulnerability |
| `search_vulnerabilities`    | Search for vulnerabilities by keyword                   |

## Installation

### Prerequisites

- Node.js 20 or higher
- TypeScript (for development)

### Building from Source

1. Clone the repository:

   ```
   git clone https://github.com/Cyreslab-AI/nessus-mcp-server.git
   cd nessus-mcp-server
   ```

2. Install dependencies:

   ```
   npm install
   ```

3. Build the server:
   ```
   npm run build
   ```

## Usage

### Running in Mock Mode

By default, the server runs in mock mode, which doesn't require a Nessus API key:

```
node build/index.js
```

### Running with a real Nessus instance

To connect to a real Nessus instance, set the following environment variables:

```
NESSUS_URL=https://your-nessus-instance:8834
NESSUS_ACCESS_KEY=your-access-key
NESSUS_SECRET_KEY=your-secret-key
```

The server is switched into real mode as soon as all three of these are set; otherwise it runs in mock mode.

Then run the server:

```
node build/index.js
```

#### Generating an API key pair

In the Nessus web UI: **Settings > My Account > API Keys > Generate**. Nessus shows the access key and secret key only once at generation time, so store them somewhere safe (e.g. a secrets manager or your MCP client's env config) - Nessus itself cannot show them to you again.

Requests authenticate with the `X-ApiKeys: accessKey=<key>; secretKey=<key>` HTTP header on every call. There is no separate login/session step, and no cookie or token to refresh.

#### Self-signed certificates

Nessus is very commonly deployed with a self-signed TLS certificate. By default this server verifies certificates strictly and will fail closed against a self-signed instance. To explicitly opt in to skipping certificate verification (e.g. for an internal instance you trust), set:

```
NESSUS_ALLOW_SELF_SIGNED=true
```

Leave this unset (or `false`) whenever the instance has a certificate issued by a trusted CA. The server logs a warning to stderr on startup whenever this is enabled.

#### Design notes on the real-mode mapping

A few of this server's tools have no exact 1:1 equivalent in the Nessus REST API, so the following judgment calls were made:

- **`start_scan`**: `scan_type` (`basic-network-scan` / `web-app-scan` / `compliance-scan`) is a logical name, not a Nessus template UUID (those are instance-specific and returned by `GET /editor/scan/templates`). This server resolves the logical name to a template by matching known template `name` values first, falling back to a fuzzy match against the template name/title. `start_scan` then creates the scan (`POST /scans`) and immediately launches it (`POST /scans/{id}/launch`), since the tool is named "start", not "create".
- **`get_scan_results`**: real scan results are aggregated per-plugin across the whole scan (from `GET /scans/{id}`'s `vulnerabilities` summary), not the fully-enriched, per-vulnerability records the mock data returns. Fetching full CVSS/description/remediation text for every plugin would mean one extra Nessus API call per finding, which does not scale for scans with many findings. Use `get_vulnerability_details` with a specific `plugin_id` from the results to drill into full detail for one finding.
- **`get_vulnerability_details`**: in mock mode this takes a CVE id. Against a real Nessus instance it must be a numeric **Nessus plugin ID** instead (e.g. `156327`), because the on-prem Nessus REST API has no endpoint that resolves an arbitrary CVE or keyword to a plugin - only `GET /plugins/plugin/{id}` (lookup by numeric plugin ID) exists. A CVE-shaped input in real mode returns a clear, documented error rather than silently failing.
- **`search_vulnerabilities`**: Nessus has no single "search all vulnerabilities" endpoint - findings only exist in the context of a scan's results. In real mode this tool accepts an optional `scan_id` to scope the search to one scan; without it, the search covers the most recently updated **completed** scans (capped at 10, to bound the number of API calls on instances with many scans). This is a deliberate scoping decision, documented on the tool description itself.

### Using with Claude for Desktop

To use this server with Claude for Desktop:

1. Edit your Claude for Desktop configuration file:

   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

2. Add the server configuration:

```json
{
  "mcpServers": {
    "nessus": {
      "command": "node",
      "args": ["/path/to/nessus-mcp-server/build/index.js"],
      "env": {
        "NESSUS_URL": "https://your-nessus-instance:8834",
        "NESSUS_ACCESS_KEY": "your-access-key",
        "NESSUS_SECRET_KEY": "your-secret-key",
        "NESSUS_ALLOW_SELF_SIGNED": "false"
      }
    }
  }
}
```

For mock mode, you can omit the `env` section.

## Example Interactions

### Starting a Scan

```
start_scan:
  target: 192.168.1.1
  scan_type: basic-network-scan
```

### Getting Scan Results

```
get_scan_results:
  scan_id: scan-1234567890
```

### Searching for Vulnerabilities

```
search_vulnerabilities:
  keyword: log4j
```

Against a real Nessus instance, optionally scope the search to one scan:

```
search_vulnerabilities:
  keyword: log4j
  scan_id: 42
```

## Development

### Project Structure

- `src/index.ts`: Main server entry point
- `src/nessus-api.ts`: Nessus API client with mock fallback
- `src/mock-data.ts`: Mock vulnerability data for testing
- `src/tools/`: Tool implementations
- `src/utils/`: Utility functions

### Adding New Tools

1. Define the tool schema and handler in the appropriate file in `src/tools/`
2. Import and register the tool in `src/index.ts`

## Verification status

Real-mode requests are implemented directly against the documented Tenable Nessus REST API contract (endpoints, request bodies, and response shapes). They have been verified by:

- A clean TypeScript build (`npm run build`).
- Exercising every tool over stdio in real mode against an unreachable `NESSUS_URL` (e.g. `https://localhost:1`), confirming the server starts, accepts requests, and returns a clean `isError` response with a descriptive message (connection refused, TLS, timeout, etc.) instead of crashing or silently falling back to mock data.

They have **not** been verified against a live Nessus instance, since none was available in the environment this was built in. If you connect this to a real instance and something doesn't match (e.g. a template name your instance doesn't have, or a response field that differs by Nessus version), please open an issue.

## License

MIT

## Disclaimer

This server is not affiliated with or endorsed by Tenable. Nessus is a trademark of Tenable, Inc.
