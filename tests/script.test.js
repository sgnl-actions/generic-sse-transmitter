import { jest } from '@jest/globals';
import { SGNL_USER_AGENT } from '@sgnl-actions/utils';

// Mock dependencies before importing script
jest.unstable_mockModule('@sgnl-ai/set-transmitter', () => ({
  transmitSET: jest.fn().mockResolvedValue({
    status: 'success',
    statusCode: 200,
    body: '{"accepted": true}',
    retryable: false
  })
}));

jest.unstable_mockModule('@sgnl-actions/utils', () => ({
  signSET: jest.fn().mockResolvedValue('mock.jwt.token'),
  getBaseURL: jest.fn((params, context) => params.address || context.environment?.ADDRESS),
  getAuthorizationHeader: jest.fn().mockResolvedValue('Bearer test-token'),
  SGNL_USER_AGENT: 'SGNL-CAEP-Hub/2.0'
}));

const { transmitSET } = await import('@sgnl-ai/set-transmitter');
const { signSET, getBaseURL, getAuthorizationHeader } = await import('@sgnl-actions/utils');
const script = await import('../src/script.mjs');

describe('Generic SSE Transmitter', () => {
  let mockContext;

  beforeEach(() => {
    jest.clearAllMocks();

    mockContext = {
      secrets: {
        BEARER_AUTH_TOKEN: 'test-bearer-token'
      },
      environment: {
        ADDRESS: 'https://default.receiver.com/events'
      },
      crypto: {
        signJWT: jest.fn().mockResolvedValue('signed.jwt.token')
      }
    };

    transmitSET.mockResolvedValue({
      status: 'success',
      statusCode: 200,
      body: '{"accepted": true}',
      retryable: false
    });
    signSET.mockResolvedValue('mock.jwt.token');
    getBaseURL.mockImplementation((params, context) => params.address || context.environment?.ADDRESS);
    getAuthorizationHeader.mockResolvedValue('Bearer test-token');
  });

  describe('invoke handler', () => {
    it('should successfully transmit a SET with required parameters', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{"initiating_entity":"policy","reason_user":"Session terminated due to policy"}',
        address: 'https://receiver.example.com/events'
      };

      const result = await script.default.invoke(params, mockContext);

      expect(result).toEqual({
        status: 'success',
        statusCode: 200,
        body: '{"accepted": true}',
        retryable: false
      });

      expect(getBaseURL).toHaveBeenCalledWith(params, mockContext);
      expect(getAuthorizationHeader).toHaveBeenCalledWith(mockContext);
      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          aud: 'https://customer.okta.com/',
          sub_id: { format: 'email', email: 'user@example.com' },
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/session-revoked': expect.objectContaining({
              initiating_entity: 'policy',
              reason_user: 'Session terminated due to policy',
              event_timestamp: expect.any(Number)
            })
          })
        })
      );

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/events',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token',
            'User-Agent': SGNL_USER_AGENT
          })
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
        eventPayload: '{}',
        address: 'https://receiver.example.com/events'
      };

      const result = await script.default.invoke(params, mockContext);
      expect(result.status).toBe('success');

      // Verify subject was added as sub_id claim
      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          sub_id: expect.objectContaining({
            user: expect.objectContaining({ format: 'email', email: 'user@example.com' }),
            session: expect.objectContaining({ format: 'opaque', id: 'session-123' })
          })
        })
      );
    });

    it('should append addressSuffix when provided', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{}',
        address: 'https://receiver.example.com',
        addressSuffix: '/caep/events'
      };

      await script.default.invoke(params, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/caep/events',
        expect.any(Object)
      );
    });

    it('should include custom claims when provided', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{}',
        address: 'https://receiver.example.com/events',
        customClaims: '{"custom_field":"value","another_field":123}'
      };

      await script.default.invoke(params, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          custom_field: 'value',
          another_field: 123
        })
      );
    });

    it('should use SubjectInEventClaims format when specified', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{}',
        address: 'https://receiver.example.com/events',
        subjectFormat: 'SubjectInEventClaims'
      };

      await script.default.invoke(params, mockContext);

      // When using SubjectInEventClaims, subject should be in event payload
      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/session-revoked': expect.objectContaining({
              subject: JSON.parse(params.subject),
              event_timestamp: expect.any(Number)
            })
          })
        })
      );

      // And sub_id claim should not be present
      const callArgs = signSET.mock.calls[0][1];
      expect(callArgs.sub_id).toBeUndefined();
    });

    it('should fail with invalid subject JSON', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: 'not-valid-json',
        eventPayload: '{}',
        address: 'https://receiver.example.com/events'
      };

      await expect(script.default.invoke(params, mockContext))
        .rejects.toThrow('Invalid subject JSON');
    });

    it('should fail with invalid eventPayload JSON', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: 'not-valid-json',
        address: 'https://receiver.example.com/events'
      };

      await expect(script.default.invoke(params, mockContext))
        .rejects.toThrow('Invalid event payload JSON');
    });

    it('should fail with non-object eventPayload', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '["array","not","object"]',
        address: 'https://receiver.example.com/events'
      };

      await expect(script.default.invoke(params, mockContext))
        .rejects.toThrow('Event payload must be a JSON object');
    });

    it('should fail with invalid customClaims JSON', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{}',
        address: 'https://receiver.example.com/events',
        customClaims: 'not-valid-json'
      };

      await expect(script.default.invoke(params, mockContext))
        .rejects.toThrow('Invalid custom claims JSON');
    });

    it('should handle transmitSET failures', async () => {
      transmitSET.mockResolvedValueOnce({
        status: 'failed',
        statusCode: 401,
        body: 'Invalid token',
        retryable: false
      });

      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{}',
        address: 'https://receiver.example.com/events'
      };

      const result = await script.default.invoke(params, mockContext);

      expect(result).toEqual({
        status: 'failed',
        statusCode: 401,
        body: 'Invalid token',
        retryable: false
      });
    });

    it('should add event_timestamp to eventPayload if not present', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{"initiating_entity":"policy"}',
        address: 'https://receiver.example.com/events'
      };

      await script.default.invoke(params, mockContext);

      expect(signSET).toHaveBeenCalledWith(
        mockContext,
        expect.objectContaining({
          events: expect.objectContaining({
            'https://schemas.openid.net/secevent/caep/event-type/session-revoked': expect.objectContaining({
              initiating_entity: 'policy',
              event_timestamp: expect.any(Number)
            })
          })
        })
      );
    });

    it('should handle addressSuffix with trailing slash correctly', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{}',
        address: 'https://receiver.example.com/',
        addressSuffix: '/caep/events'
      };

      await script.default.invoke(params, mockContext);

      expect(transmitSET).toHaveBeenCalledWith(
        'mock.jwt.token',
        'https://receiver.example.com/caep/events',
        expect.any(Object)
      );
    });

    it('should use ADDRESS from environment when address not provided', async () => {
      const params = {
        type: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        audience: 'https://customer.okta.com/',
        subject: '{"format":"email","email":"user@example.com"}',
        eventPayload: '{}'
      };

      await script.default.invoke(params, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(
        params,
        mockContext
      );
    });
  });

  describe('error handler', () => {
    it('should request retry for 429 error', async () => {
      const params = {
        error: new Error('SET transmission failed: 429 Too Many Requests')
      };

      const result = await script.default.error(params, mockContext);
      expect(result).toEqual({ status: 'retry_requested' });
    });

    it('should request retry for 502 error', async () => {
      const params = {
        error: new Error('SET transmission failed: 502 Bad Gateway')
      };

      const result = await script.default.error(params, mockContext);
      expect(result).toEqual({ status: 'retry_requested' });
    });

    it('should request retry for 503 error', async () => {
      const params = {
        error: new Error('SET transmission failed: 503 Service Unavailable')
      };

      const result = await script.default.error(params, mockContext);
      expect(result).toEqual({ status: 'retry_requested' });
    });

    it('should request retry for 504 error', async () => {
      const params = {
        error: new Error('SET transmission failed: 504 Gateway Timeout')
      };

      const result = await script.default.error(params, mockContext);
      expect(result).toEqual({ status: 'retry_requested' });
    });

    it('should re-throw non-retryable errors', async () => {
      const params = {
        error: new Error('SET transmission failed: 401 Unauthorized')
      };

      await expect(script.default.error(params, mockContext))
        .rejects.toThrow('SET transmission failed: 401 Unauthorized');
    });

    it('should re-throw generic errors', async () => {
      const params = {
        error: new Error('Some other error')
      };

      await expect(script.default.error(params, mockContext))
        .rejects.toThrow('Some other error');
    });
  });

  describe('halt handler', () => {
    it('should return halted status', async () => {
      const params = {};
      const result = await script.default.halt(params, mockContext);

      expect(result).toEqual({ status: 'halted' });
    });
  });
});
