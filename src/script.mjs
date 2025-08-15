import { createBuilder } from '@sgnl-ai/secevent';

/**
 * Transmits a Security Event Token (SET) to the specified endpoint
 * @param {string} url - The destination URL
 * @param {string} jwt - The signed JWT to transmit
 * @param {string} [authToken] - Optional bearer token for authentication
 * @returns {Promise<Response>} The HTTP response
 */
async function transmitSET(url, jwt, authToken) {
  const headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/secevent+jwt',
    'User-Agent': 'SGNL-Action-Framework/1.0'
  };

  if (authToken) {
    headers['Authorization'] = authToken.startsWith('Bearer ')
      ? authToken
      : `Bearer ${authToken}`;
  }

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: jwt
  });

  return response;
}

/**
 * Parse subject JSON string into the appropriate format
 * @param {string} subjectStr - JSON string representing the subject
 * @returns {object} Parsed subject object
 */
function parseSubject(subjectStr) {
  try {
    return JSON.parse(subjectStr);
  } catch (error) {
    throw new Error(`Invalid subject JSON: ${error.message}`);
  }
}

/**
 * Build the destination URL from address and optional suffix
 * @param {string} address - Base address
 * @param {string} [suffix] - Optional suffix to append
 * @returns {string} Complete URL
 */
function buildUrl(address, suffix) {
  if (!suffix) {
    return address;
  }

  const baseUrl = address.endsWith('/') ? address.slice(0, -1) : address;
  const cleanSuffix = suffix.startsWith('/') ? suffix.slice(1) : suffix;

  return `${baseUrl}/${cleanSuffix}`;
}

export default {
  /**
   * Main handler for transmitting Security Event Tokens
   */
  invoke: async (params, context) => {
    // Validate required parameters
    if (!params.type) {
      throw new Error('type is required');
    }
    if (!params.audience) {
      throw new Error('audience is required');
    }
    if (!params.subject) {
      throw new Error('subject is required');
    }
    if (!params.eventPayload) {
      throw new Error('eventPayload is required');
    }

    // Get secrets
    const ssfKey = context.secrets?.SSF_KEY;
    const ssfKeyId = context.secrets?.SSF_KEY_ID;
    const authToken = context.secrets?.AUTH_TOKEN;

    if (!ssfKey) {
      throw new Error('SSF_KEY secret is required');
    }
    if (!ssfKeyId) {
      throw new Error('SSF_KEY_ID secret is required');
    }

    // Get optional parameters with defaults
    const issuer = params.issuer || 'https://sgnl.ai/';
    const signingMethod = params.signingMethod || 'RS256';

    // Parse the subject
    const subject = parseSubject(params.subject);

    // Ensure event_timestamp is set
    const eventPayload = {
      ...params.eventPayload,
      event_timestamp: Math.floor(Date.now() / 1000)
    };

    // Determine subject format (default to SubjectInSubId for CAEP 3.0)
    const subjectFormat = params.subjectFormat || 'SubjectInSubId';

    // Create the SET builder
    const builder = createBuilder();

    // Configure the builder
    builder
      .withIssuer(issuer)
      .withAudience(params.audience)
      .withIat(Math.floor(Date.now() / 1000));

    // Add subject based on format
    if (subjectFormat === 'SubjectInEventClaims') {
      // Add subject to event payload for CAEP 2.0
      eventPayload.subject = subject;
    } else {
      // Add subject as sub_id for CAEP 3.0
      builder.withClaim('sub_id', subject);
    }

    // Add the event with its payload
    builder.withEvent(params.type, eventPayload);

    // Add custom claims if provided
    if (params.customClaims) {
      Object.entries(params.customClaims).forEach(([key, value]) => {
        builder.withClaim(key, value);
      });
    }

    // Sign and get the JWT
    builder.withSigningKey(ssfKey, ssfKeyId, signingMethod);
    const jwt = await builder.sign();

    // Determine the destination URL
    // If address is provided, use it; otherwise fail as we need a destination
    if (!params.address && !context.environment?.SET_RECEIVER_URL) {
      throw new Error('address parameter or SET_RECEIVER_URL environment variable is required');
    }

    const url = buildUrl(
      params.address || context.environment?.SET_RECEIVER_URL,
      params.addressSuffix
    );

    // Transmit the SET
    const response = await transmitSET(url, jwt, authToken);

    // Read response body
    const responseBody = await response.text();

    // Return response with proper status
    const result = {
      status: response.ok ? 'success' : 'failed',
      statusCode: response.status,
      body: responseBody
    };

    // If not successful, include error details
    if (!response.ok) {
      const errorMessage = `SET transmission failed: ${response.status} ${response.statusText}`;
      if (response.status >= 500 || response.status === 429) {
        // Server errors and rate limits are retryable
        throw new Error(errorMessage);
      } else {
        // Client errors are fatal
        result.error = errorMessage;
      }
    }

    return result;
  },

  /**
   * Error handler for retryable failures
   */
  error: async (params, _context) => {
    const { error } = params;

    // Check if this is a retryable error
    if (error.message?.includes('429') ||
        error.message?.includes('502') ||
        error.message?.includes('503') ||
        error.message?.includes('504')) {
      // These are retryable - let the framework handle retry
      return { status: 'retry_requested' };
    }

    // Non-retryable errors (401, 403, 404, etc)
    throw error;
  },

  /**
   * Cleanup handler
   */
  halt: async (_params, _context) => {
    // No cleanup needed for this action
    return { status: 'halted' };
  }
};