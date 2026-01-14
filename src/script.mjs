import { getAuthorizationHeader, getBaseURL, resolveJSONPathTemplates, signSET } from '@sgnl-actions/utils';
import { transmitSET } from '@sgnl-ai/set-transmitter';

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
 * Parse event payload JSON string
 * @param {string} payloadStr - JSON string representing the event payload
 * @returns {object} Parsed payload object
 */
function parseEventPayload(payloadStr) {
  try {
    const payload = JSON.parse(payloadStr);
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
      throw new Error('Event payload must be a JSON object');
    }
    return payload;
  } catch (error) {
    throw new Error(`Invalid event payload JSON: ${error.message}`);
  }
}

/**
 * Parse custom claims JSON string
 * @param {string} claimsStr - JSON string representing custom claims
 * @returns {object} Parsed claims object
 */
function parseCustomClaims(claimsStr) {
  try {
    const claims = JSON.parse(claimsStr);
    if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) {
      throw new Error('Custom claims must be a JSON object');
    }
    return claims;
  } catch (error) {
    throw new Error(`Invalid custom claims JSON: ${error.message}`);
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
   * Main execution handler - transmits a generic Security Event Token
   *
   * @param {Object} params - Job input parameters
   * @param {string} params.type - Security event type URI (e.g., https://schemas.openid.net/secevent/caep/event-type/session-revoked)
   * @param {string} params.audience - Intended recipient of the SET (e.g., https://customer.okta.com/)
   * @param {string} params.subject - Subject identifier JSON (simple or complex format)
   * @param {Object} params.eventPayload - Event-specific payload data
   * @param {string} params.address - Optional destination URL override (defaults to ADDRESS environment variable)
   * @param {string} params.addressSuffix - Optional suffix to append to the address
   * @param {Object} params.customClaims - Optional custom claims to add to the JWT
   * @param {string} params.subjectFormat - Subject format (SubjectInEventClaims or SubjectInSubId, defaults to SubjectInSubId)
   *
   * @param {Object} context - Execution context with secrets and environment
   * @param {Object} context.environment - Environment configuration
   * @param {string} context.environment.ADDRESS - Default destination URL for the SET transmission
   *
   * The configured auth type will determine which of the following environment variables and secrets are available
   * @param {string} context.secrets.BEARER_AUTH_TOKEN
   *
   * @param {string} context.secrets.BASIC_USERNAME
   * @param {string} context.secrets.BASIC_PASSWORD
   *
   * @param {string} context.secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL
   *
   * @param {string} context.secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN
   *
   * @param {Object} context.crypto - Cryptographic operations API
   * @param {Function} context.crypto.signJWT - Function to sign JWTs with server-side keys
   *
   * @returns {Object} Transmission result with status, statusCode, body, and retryable flag
   */
  invoke: async (params, context) => {
    const jobContext = context.data || {};

    // Resolve JSONPath templates in params
    const { result: resolvedParams, errors } = resolveJSONPathTemplates(params, jobContext);
    if (errors.length > 0) {
      console.warn('Template resolution errors:', errors);
    }

    // Get the base address
    const baseAddress = getBaseURL(resolvedParams, context);

    // Build complete URL with optional suffix
    const address = buildUrl(baseAddress, resolvedParams.addressSuffix);

    const authHeader = await getAuthorizationHeader(context);

    // Parse the subject
    const subject = parseSubject(resolvedParams.subject);

    // Parse the event payload
    const parsedEventPayload = parseEventPayload(resolvedParams.eventPayload);

    // Build event payload with current timestamp
    const eventPayload = {
      ...parsedEventPayload,
      event_timestamp: Math.floor(Date.now() / 1000),
    };

    // Determine subject format (default to SubjectInSubId for CAEP 3.0)
    const subjectFormat = resolvedParams.subjectFormat || 'SubjectInSubId';

    // Start with custom claims (if provided), then override with required fields
    const setPayload = {};

    // Add custom claims first
    if (resolvedParams.customClaims) {
      const customClaims = parseCustomClaims(resolvedParams.customClaims);
      Object.entries(customClaims).forEach(([key, value]) => {
        setPayload[key] = value;
      });
    }

    // Build the required SET structure (overrides any custom claims with same keys)
    setPayload.aud = resolvedParams.audience;
    setPayload.events = {
      [resolvedParams.type]: eventPayload,
    };

    // Add subject based on format
    if (subjectFormat === 'SubjectInEventClaims') {
      // Add subject to event payload for CAEP 2.0 or Okta events
      setPayload.events[resolvedParams.type].subject = subject;
    } else {
      // Add subject as sub_id for CAEP 3.0
      setPayload.sub_id = subject;
    }

    // Sign the SET
    const jwt = await signSET(context, setPayload);

    // Transmit the SET
    return await transmitSET(jwt, address, {
      headers: {
        Authorization: authHeader,
        'User-Agent': 'SGNL-CAEP-Hub/2.0',
      },
    });
  },

  /**
   * Error handler for retryable failures
   */
  error: async (params, _context) => {
    const { error } = params;

    // Check if this is a retryable error
    if (
      error.message?.includes('429') ||
      error.message?.includes('502') ||
      error.message?.includes('503') ||
      error.message?.includes('504')
    ) {
      return { status: 'retry_requested' };
    }

    // Non-retryable error
    throw error;
  },

  /**
   * Cleanup handler
   */
  halt: async (_params, _context) => {
    return { status: 'halted' };
  },
};
