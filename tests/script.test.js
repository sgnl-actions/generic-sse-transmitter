import { jest } from '@jest/globals';

// Mock fetch globally
global.fetch = jest.fn();

// Mock the crypto module
jest.unstable_mockModule('crypto', () => ({
  createPrivateKey: jest.fn((key) => ({ type: 'private', asymmetricKeyType: 'rsa' }))
}));

// Mock @sgnl-ai/secevent module
jest.unstable_mockModule('@sgnl-ai/secevent', () => {
  const mockBuilder = {
    withIssuer: jest.fn().mockReturnThis(),
    withAudience: jest.fn().mockReturnThis(),
    withIat: jest.fn().mockReturnThis(),
    withClaim: jest.fn().mockReturnThis(),
    withEvent: jest.fn().mockReturnThis(),
    sign: jest.fn().mockResolvedValue({ jwt: 'mocked.jwt.token' })
  };
  
  return {
    createBuilder: jest.fn(() => mockBuilder)
  };
});

// Import after mocking
const script = (await import('../src/script.mjs')).default;
const { createBuilder } = await import('@sgnl-ai/secevent');

describe('Generic SSE Transmitter', () => {
  let mockContext;
  let mockBuilder;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Get the mock builder
    mockBuilder = createBuilder();
    
    mockContext = {
      secrets: {
        SSF_KEY: `-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCxFPks6MertTFK
test-key-content
-----END PRIVATE KEY-----`,
        SSF_KEY_ID: 'test-key-id',
        AUTH_TOKEN: 'Bearer test-token'
      },
      environment: {}
    };

    // Default fetch mock - successful response
    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      statusText: 'OK',
      text: jest.fn().mockResolvedValue('{"accepted": true}')
    });
  });

  describe('invoke handler', () => {
    it('should successfully transmit a SET with required parameters', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {
          initiating_entity: 'policy',
          reason_user: 'Session terminated due to policy'
        },
        address: 'https://receiver.example.com/events'
      };

      const result = await script.invoke(params, mockContext);

      expect(result).toEqual({
        status: 'success',
        statusCode: 200,
        body: '{"accepted": true}'
      });

      expect(global.fetch).toHaveBeenCalledWith(
        'https://receiver.example.com/events',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/secevent+jwt',
            'Accept': 'application/json',
            'Authorization': 'Bearer test-token'
          }),
          body: 'mocked.jwt.token'
        })
      );

      expect(mockBuilder.withAudience).toHaveBeenCalledWith('https://customer.okta.com/');
      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        expect.objectContaining({
          initiating_entity: 'policy',
          reason_user: 'Session terminated due to policy',
          event_timestamp: expect.any(Number)
        })
      );
    });

    it('should handle complex subject format', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: JSON.stringify({
          user: { format: 'email', email: 'user@example.com' },
          session: { format: 'opaque', id: 'session-123' }
        }),
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      const result = await script.invoke(params, mockContext);
      expect(result.status).toBe('success');
      
      // Verify subject was added as sub_id claim
      expect(mockBuilder.withClaim).toHaveBeenCalledWith(
        'sub_id',
        expect.objectContaining({
          user: expect.objectContaining({ format: 'email', email: 'user@example.com' }),
          session: expect.objectContaining({ format: 'opaque', id: 'session-123' })
        })
      );
    });

    it('should append addressSuffix when provided', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com',
        addressSuffix: '/caep/events'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://receiver.example.com/caep/events',
        expect.any(Object)
      );
    });

    it('should include custom claims when provided', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events',
        customClaims: {
          custom_field: 'value',
          another_field: 123
        }
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.withClaim).toHaveBeenCalledWith('custom_field', 'value');
      expect(mockBuilder.withClaim).toHaveBeenCalledWith('another_field', 123);
    });

    it('should use custom issuer when provided', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events',
        issuer: 'https://custom.issuer.com/'
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.withIssuer).toHaveBeenCalledWith('https://custom.issuer.com/');
    });

    it('should use SubjectInEventClaims format when specified', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events',
        subjectFormat: 'SubjectInEventClaims'
      };

      await script.invoke(params, mockContext);

      // When using SubjectInEventClaims, subject should be in event payload
      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        expect.objectContaining({
          subject: JSON.parse(params.subject),
          event_timestamp: expect.any(Number)
        })
      );
      
      // And sub_id claim should not be added
      expect(mockBuilder.withClaim).not.toHaveBeenCalledWith(
        'sub_id',
        expect.anything()
      );
    });

    it('should fail when required type is missing', async () => {
      const params = {
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('type is required');
    });

    it('should fail when required audience is missing', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('audience is required');
    });

    it('should fail when required subject is missing', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('subject is required');
    });

    it('should fail when SSF_KEY secret is missing', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      delete mockContext.secrets.SSF_KEY;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('SSF_KEY secret is required');
    });

    it('should fail when SSF_KEY_ID secret is missing', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      delete mockContext.secrets.SSF_KEY_ID;

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('SSF_KEY_ID secret is required');
    });

    it('should fail when address is not provided', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {}
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('address parameter or SET_RECEIVER_URL environment variable is required');
    });

    it('should fail with invalid subject JSON', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: 'not-valid-json',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('Invalid subject JSON');
    });

    it('should throw on 429 rate limit error', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        text: jest.fn().mockResolvedValue('Rate limited')
      });

      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('SET transmission failed: 429 Too Many Requests');
    });

    it('should throw on 500 server error', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        text: jest.fn().mockResolvedValue('Server error')
      });

      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      await expect(script.invoke(params, mockContext))
        .rejects.toThrow('SET transmission failed: 500 Internal Server Error');
    });

    it('should return failed status for 401 error', async () => {
      global.fetch.mockResolvedValue({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        text: jest.fn().mockResolvedValue('Invalid token')
      });

      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      const result = await script.invoke(params, mockContext);

      expect(result).toEqual({
        status: 'failed',
        statusCode: 401,
        body: 'Invalid token',
        error: 'SET transmission failed: 401 Unauthorized'
      });
    });

    it('should not include auth header when AUTH_TOKEN is missing', async () => {
      delete mockContext.secrets.AUTH_TOKEN;

      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.not.objectContaining({
            'Authorization': expect.any(String)
          })
        })
      );
    });

    it('should add event_timestamp to eventPayload', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {
          initiating_entity: 'policy'
        },
        address: 'https://receiver.example.com/events'
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.withEvent).toHaveBeenCalledWith(
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        expect.objectContaining({
          initiating_entity: 'policy',
          event_timestamp: expect.any(Number)
        })
      );
    });

    it('should use custom signing method when provided', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/events',
        signingMethod: 'RS384'
      };

      await script.invoke(params, mockContext);

      expect(mockBuilder.sign).toHaveBeenCalledWith(
        expect.objectContaining({
          alg: 'RS384'
        })
      );
    });

    it('should handle addressSuffix with trailing slash correctly', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {},
        address: 'https://receiver.example.com/',
        addressSuffix: '/caep/events'
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://receiver.example.com/caep/events',
        expect.any(Object)
      );
    });

    it('should use SET_RECEIVER_URL from environment when address not provided', async () => {
      mockContext.environment.SET_RECEIVER_URL = 'https://env.receiver.com/events';

      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: {}
      };

      await script.invoke(params, mockContext);

      expect(global.fetch).toHaveBeenCalledWith(
        'https://env.receiver.com/events',
        expect.any(Object)
      );
    });
  });

  describe('error handler', () => {
    it('should request retry for 429 error', async () => {
      const params = {
        error: new Error('SET transmission failed: 429 Too Many Requests')
      };

      const result = await script.error(params, mockContext);
      expect(result).toEqual({ status: 'retry_requested' });
    });

    it('should request retry for 502 error', async () => {
      const params = {
        error: new Error('SET transmission failed: 502 Bad Gateway')
      };

      const result = await script.error(params, mockContext);
      expect(result).toEqual({ status: 'retry_requested' });
    });

    it('should request retry for 503 error', async () => {
      const params = {
        error: new Error('SET transmission failed: 503 Service Unavailable')
      };

      const result = await script.error(params, mockContext);
      expect(result).toEqual({ status: 'retry_requested' });
    });

    it('should request retry for 504 error', async () => {
      const params = {
        error: new Error('SET transmission failed: 504 Gateway Timeout')
      };

      const result = await script.error(params, mockContext);
      expect(result).toEqual({ status: 'retry_requested' });
    });

    it('should re-throw non-retryable errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 401 Unauthorized')
      };

      await expect(script.error(params, mockContext))
        .rejects.toThrow('SET transmission failed: 401 Unauthorized');
    });

    it('should re-throw generic errors', async () => {
      const params = {
        error: new Error('Some other error')
      };

      await expect(script.error(params, mockContext))
        .rejects.toThrow('Some other error');
    });
  });

  describe('halt handler', () => {
    it('should return halted status', async () => {
      const params = {};
      const result = await script.halt(params, mockContext);

      expect(result).toEqual({ status: 'halted' });
    });
  });
});