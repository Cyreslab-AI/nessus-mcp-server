/**
 * Error handling utilities for the Nessus MCP server
 */

import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

/**
 * Custom error types for the Nessus MCP server
 */
export enum NessusErrorType {
  SCAN_NOT_FOUND = 'scan_not_found',
  VULNERABILITY_NOT_FOUND = 'vulnerability_not_found',
  INVALID_SCAN_TYPE = 'invalid_scan_type',
  INVALID_TARGET = 'invalid_target',
  SCAN_IN_PROGRESS = 'scan_in_progress',
  API_ERROR = 'api_error',
  CONFIGURATION_ERROR = 'configuration_error'
}

/**
 * Create a standardized MCP error from a Nessus error
 * @param type Error type
 * @param message Error message
 * @param details Additional error details
 */
export const createNessusError = (
  type: NessusErrorType,
  message: string,
  details?: unknown
): McpError => {
  let code: ErrorCode;

  // Map Nessus error types to MCP error codes
  switch (type) {
    case NessusErrorType.SCAN_NOT_FOUND:
    case NessusErrorType.VULNERABILITY_NOT_FOUND:
      code = ErrorCode.InvalidParams;
      break;
    case NessusErrorType.INVALID_SCAN_TYPE:
    case NessusErrorType.INVALID_TARGET:
      code = ErrorCode.InvalidParams;
      break;
    case NessusErrorType.API_ERROR:
      code = ErrorCode.InternalError;
      break;
    case NessusErrorType.CONFIGURATION_ERROR:
      code = ErrorCode.InternalError;
      break;
    default:
      code = ErrorCode.InternalError;
  }

  return new McpError(code, message, details);
};

/**
 * Handle errors from the Nessus API and convert them to MCP errors
 * @param error Error from the Nessus API
 */
export const handleNessusApiError = (error: unknown): McpError => {
  if (error instanceof McpError) {
    return error;
  }

  if (error instanceof Error) {
    // Check for specific error messages from the Nessus API
    if (error.message.includes('not found')) {
      return createNessusError(
        NessusErrorType.SCAN_NOT_FOUND,
        'The requested scan was not found',
        error
      );
    }

    if (error.message.includes('invalid scan type')) {
      return createNessusError(
        NessusErrorType.INVALID_SCAN_TYPE,
        'The specified scan type is not valid',
        error
      );
    }

    // Generic error handling
    return createNessusError(
      NessusErrorType.API_ERROR,
      `Nessus API error: ${error.message}`,
      error
    );
  }

  // Unknown error type
  return createNessusError(
    NessusErrorType.API_ERROR,
    'Unknown Nessus API error',
    error
  );
};

/**
 * Validate that a scan ID is provided and in the correct format
 * @param scanId Scan ID to validate
 */
export const validateScanId = (scanId: unknown): string => {
  if (!scanId) {
    throw createNessusError(
      NessusErrorType.SCAN_NOT_FOUND,
      'Scan ID is required'
    );
  }

  if (typeof scanId !== 'string') {
    throw createNessusError(
      NessusErrorType.SCAN_NOT_FOUND,
      'Scan ID must be a string'
    );
  }

  return scanId;
};

/**
 * Validate that a vulnerability ID is provided and in the correct format
 * @param vulnId Vulnerability ID to validate
 */
export const validateVulnerabilityId = (vulnId: unknown): string => {
  if (!vulnId) {
    throw createNessusError(
      NessusErrorType.VULNERABILITY_NOT_FOUND,
      'Vulnerability ID is required'
    );
  }

  if (typeof vulnId !== 'string') {
    throw createNessusError(
      NessusErrorType.VULNERABILITY_NOT_FOUND,
      'Vulnerability ID must be a string'
    );
  }

  return vulnId;
};

/**
 * Validate that a target is provided and in the correct format
 * @param target Target to validate
 */
export const validateTarget = (target: unknown): string => {
  if (!target) {
    throw createNessusError(
      NessusErrorType.INVALID_TARGET,
      'Target is required'
    );
  }

  if (typeof target !== 'string') {
    throw createNessusError(
      NessusErrorType.INVALID_TARGET,
      'Target must be a string'
    );
  }

  // Basic validation for IP address or hostname
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!ipRegex.test(target)) {
    throw createNessusError(
      NessusErrorType.INVALID_TARGET,
      'Target must be a valid IP address or hostname'
    );
  }

  return target;
};

/**
 * Validate that a scan type is provided and in the correct format
 * @param scanType Scan type to validate
 * @param validTypes List of valid scan types
 */
export const validateScanType = (
  scanType: unknown,
  validTypes: string[] = ['basic-network-scan', 'web-app-scan', 'compliance-scan']
): string => {
  if (!scanType) {
    throw createNessusError(
      NessusErrorType.INVALID_SCAN_TYPE,
      'Scan type is required'
    );
  }

  if (typeof scanType !== 'string') {
    throw createNessusError(
      NessusErrorType.INVALID_SCAN_TYPE,
      'Scan type must be a string'
    );
  }

  if (!validTypes.includes(scanType)) {
    throw createNessusError(
      NessusErrorType.INVALID_SCAN_TYPE,
      `Scan type must be one of: ${validTypes.join(', ')}`
    );
  }

  return scanType;
};
