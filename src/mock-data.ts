/**
 * Mock data for Nessus vulnerability scanner
 * This file provides sample data for testing the MCP server without an actual Nessus API connection
 */

// Mock scan types
export const scanTemplates = [
  {
    id: "basic-network-scan",
    name: "Basic Network Scan",
    description: "Standard network vulnerability assessment",
    capabilities: ["OS detection", "Service discovery", "Vulnerability detection"]
  },
  {
    id: "web-app-scan",
    name: "Web Application Scan",
    description: "Comprehensive web application security assessment",
    capabilities: ["SQL injection", "XSS detection", "CSRF testing", "Authentication testing"]
  },
  {
    id: "compliance-scan",
    name: "Compliance Scan",
    description: "Regulatory compliance assessment",
    capabilities: ["PCI DSS", "HIPAA", "SOX", "GDPR"]
  }
];

// Mock scan statuses
export const scanStatuses = {
  "running": "The scan is currently in progress",
  "completed": "The scan has finished successfully",
  "failed": "The scan encountered an error and could not complete",
  "paused": "The scan has been paused by the user",
  "canceled": "The scan was canceled by the user",
  "queued": "The scan is waiting to start"
};

// Mock vulnerability severity levels
export const severityLevels = {
  "critical": 4,
  "high": 3,
  "medium": 2,
  "low": 1,
  "info": 0
};

// Mock vulnerability data
export const vulnerabilities = [
  {
    id: "CVE-2021-44228",
    name: "Log4Shell",
    description: "Remote code execution vulnerability in Apache Log4j",
    severity: "critical",
    cvss_score: 10.0,
    affected_systems: ["Java applications using Log4j 2.0-2.14.1"],
    remediation: "Update to Log4j 2.15.0 or later",
    references: [
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
      "https://logging.apache.org/log4j/2.x/security.html"
    ]
  },
  {
    id: "CVE-2023-23397",
    name: "Microsoft Outlook Elevation of Privilege",
    description: "Microsoft Outlook vulnerability allowing privilege escalation",
    severity: "high",
    cvss_score: 9.8,
    affected_systems: ["Microsoft Outlook for Windows"],
    remediation: "Install latest Microsoft security updates",
    references: [
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-23397"
    ]
  },
  {
    id: "CVE-2022-22965",
    name: "Spring4Shell",
    description: "Remote code execution vulnerability in Spring Framework",
    severity: "critical",
    cvss_score: 9.8,
    affected_systems: ["Spring Framework 5.3.0 to 5.3.17", "Spring Framework 5.2.0 to 5.2.19"],
    remediation: "Update to Spring Framework 5.3.18+ or 5.2.20+",
    references: [
      "https://tanzu.vmware.com/security/cve-2022-22965"
    ]
  },
  {
    id: "CVE-2021-34527",
    name: "PrintNightmare",
    description: "Windows Print Spooler remote code execution vulnerability",
    severity: "critical",
    cvss_score: 8.8,
    affected_systems: ["Windows Print Spooler service"],
    remediation: "Install Microsoft security updates and disable Print Spooler when not needed",
    references: [
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
    ]
  },
  {
    id: "CVE-2021-26855",
    name: "ProxyLogon",
    description: "Microsoft Exchange Server vulnerability",
    severity: "critical",
    cvss_score: 9.8,
    affected_systems: ["Microsoft Exchange Server 2013-2019"],
    remediation: "Install security updates for Exchange Server",
    references: [
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"
    ]
  },
  {
    id: "CVE-2022-30190",
    name: "Follina",
    description: "Microsoft Support Diagnostic Tool vulnerability",
    severity: "high",
    cvss_score: 7.8,
    affected_systems: ["Microsoft Office"],
    remediation: "Apply Microsoft security updates",
    references: [
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190"
    ]
  },
  {
    id: "CVE-2020-1472",
    name: "Zerologon",
    description: "Windows Netlogon elevation of privilege vulnerability",
    severity: "critical",
    cvss_score: 10.0,
    affected_systems: ["Windows Server 2008-2019"],
    remediation: "Install August 2020 security update and enable enforcement mode",
    references: [
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"
    ]
  },
  {
    id: "CVE-2019-19781",
    name: "Citrix ADC Vulnerability",
    description: "Directory traversal vulnerability in Citrix ADC and Gateway",
    severity: "critical",
    cvss_score: 9.8,
    affected_systems: ["Citrix ADC and Gateway 10.5-13.0"],
    remediation: "Apply Citrix security updates",
    references: [
      "https://support.citrix.com/article/CTX267027"
    ]
  },
  {
    id: "CVE-2021-40444",
    name: "MSHTML Remote Code Execution",
    description: "Microsoft MSHTML remote code execution vulnerability",
    severity: "high",
    cvss_score: 8.8,
    affected_systems: ["Windows with Microsoft Office"],
    remediation: "Install Microsoft security updates",
    references: [
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444"
    ]
  },
  {
    id: "CVE-2021-3156",
    name: "Sudo Baron Samedit",
    description: "Heap-based buffer overflow in Sudo",
    severity: "high",
    cvss_score: 7.8,
    affected_systems: ["Unix/Linux systems with Sudo 1.8.2-1.8.31p2"],
    remediation: "Update Sudo to version 1.9.5p2 or later",
    references: [
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3156"
    ]
  }
];

// Mock scan results
export const generateMockScanResults = (targetIp: string, scanType: string) => {
  // Randomly select 3-7 vulnerabilities
  const numVulns = Math.floor(Math.random() * 5) + 3;
  const selectedVulns = [...vulnerabilities]
    .sort(() => 0.5 - Math.random())
    .slice(0, numVulns);

  // Generate scan metadata
  const scanId = `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const startTime = new Date(Date.now() - Math.random() * 3600000);
  const endTime = new Date(startTime.getTime() + (Math.random() * 3600000));

  return {
    scan_id: scanId,
    scan_type: scanType,
    target: targetIp,
    start_time: startTime.toISOString(),
    end_time: endTime.toISOString(),
    status: "completed",
    summary: {
      total_hosts: 1,
      total_vulnerabilities: selectedVulns.length,
      critical: selectedVulns.filter(v => v.severity === "critical").length,
      high: selectedVulns.filter(v => v.severity === "high").length,
      medium: selectedVulns.filter(v => v.severity === "medium").length,
      low: selectedVulns.filter(v => v.severity === "low").length,
      info: selectedVulns.filter(v => v.severity === "info").length
    },
    vulnerabilities: selectedVulns
  };
};

// Mock scans database
export const mockScans = new Map();

// Function to create a new mock scan
export const createMockScan = (target: string, scanType: string) => {
  const scanId = `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const scan = {
    id: scanId,
    target: target,
    type: scanType,
    status: "queued",
    created: new Date().toISOString(),
    results: null
  };

  mockScans.set(scanId, scan);

  // Simulate scan progression
  setTimeout(() => {
    const scan = mockScans.get(scanId);
    if (scan) {
      scan.status = "running";
      mockScans.set(scanId, scan);
    }
  }, 2000);

  setTimeout(() => {
    const scan = mockScans.get(scanId);
    if (scan) {
      scan.status = "completed";
      scan.results = generateMockScanResults(target, scanType);
      mockScans.set(scanId, scan);
    }
  }, 10000);

  return scanId;
};

// Function to get scan status
export const getMockScanStatus = (scanId: string) => {
  const scan = mockScans.get(scanId);
  if (!scan) {
    return { error: "Scan not found" };
  }

  return {
    id: scan.id,
    status: scan.status,
    target: scan.target,
    type: scan.type,
    created: scan.created
  };
};

// Function to get scan results
export const getMockScanResults = (scanId: string) => {
  const scan = mockScans.get(scanId);
  if (!scan) {
    return { error: "Scan not found" };
  }

  if (scan.status !== "completed") {
    return {
      error: "Scan results not available",
      status: scan.status
    };
  }

  return scan.results;
};

// Function to get vulnerability details
export const getMockVulnerabilityDetails = (vulnId: string) => {
  const vuln = vulnerabilities.find(v => v.id === vulnId);
  if (!vuln) {
    return { error: "Vulnerability not found" };
  }

  return vuln;
};
