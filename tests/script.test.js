import { jest } from '@jest/globals';
import script from '../src/script.mjs';

// Mock fetch globally
global.fetch = jest.fn();

// Create a manual mock for @sgnl-ai/secevent
const mockBuilder = {
  withIssuer: jest.fn().mockReturnThis(),
  withAudience: jest.fn().mockReturnThis(),
  withIat: jest.fn().mockReturnThis(),
  withClaim: jest.fn().mockReturnThis(),
  withEvent: jest.fn().mockReturnThis(),
  withSigningKey: jest.fn().mockReturnThis(),
  sign: jest.fn().mockResolvedValue('signed.jwt.token')
};

jest.unstable_mockModule('@sgnl-ai/secevent', () => ({
  createBuilder: jest.fn(() => mockBuilder)
}));

describe('Generic SSE Transmitter', () => {
  let mockContext;

  beforeEach(() => {
    jest.clearAllMocks();

    // Reset mock builder methods
    Object.keys(mockBuilder).forEach(key => {
      if (typeof mockBuilder[key].mockClear === 'function') {
        mockBuilder[key].mockClear();
        if (key !== 'sign') {
          mockBuilder[key].mockReturnValue(mockBuilder);
        }
      }
    });
    mockBuilder.sign.mockResolvedValue('signed.jwt.token');

    mockContext = {
      secrets: {
        SSF_KEY: `-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCxFPks6MertTFK
GpIssuiDlZZNvUq9kV1lTc90YrPvZKMdfoOzBxjdn4x7i5dWnP8oKL7Tbl5HcyMd
LSvv3Jf1KCDQvq5jL18igC70v3nGQNjbTp9Gu/c644WHNyHr3iWDRb/GZac70CM7
ihqMw/35bf9KZGOCX8TNPWTWpTmsyFVzEIp6G6AI0UXQGKu8gXxFPxKQfPmCSVJ3
sDLcYnoAnA1oM9IauBtU6JBUHn1mjYHqvbuGvi726dVobdurcDJGty+Szia60R/N
3uw8ylxrLmKws/vVG0q0tnyqKrz6/bIvt3eX21PW3TYeDFXFbQHJzYieIzk5Cgsj
lDFZlRcjAgMBAAECgf8Dze+Mh3PCvKHSdb+uNinIqe4QvYBdkkHvazyJw5UaD49x
ksZBkmV2XXcnMFiQA893jWiMIlLkNhULC21mOdcJ7VLHKVGVz+67TwWzPGnhWINQ
MuA5JNCq8zhrL0QLTTqBF36HRKfTISWgodbwL0XFlhdmAcIhiu0ve6Iu+l3C2IHX
ZML7ii0q5GOSBt74nYVll47jRbiqPF7pbP0txfnauoicaAbnofXSTrfGLz9DJnjp
ACyqo03Dmey11BYz/DeP3nOOrBU0p+hQdMycrP2sdUt0GyBqoI8M8rvHqbWmMqhz
kA6flGazQNK4QinEIGG8f2WB10OqK7JtRISk7fUCgYEA1Sz+wA10PEpF+kXMYGCB
B79zwb/Ci1xOWBEsGf9pah6fW6b8vG/r16knujCF2XnvH13GP3f2RATJWthnsRT7
J+APTEhZc9LyZyNRRjFhnT82dQx8ZFyf7VtN37xSVpQa7LltTGAlW3o9CQQ6jEuy
Ps+NDLrWp7iIQlpP6Eb9lxUCgYEA1KfHLUdaK4zOe9QJNC4YFt2e3WRA/LOcOVi3
Qorx22QZLZV2e4wYXROnuxDdd9ofGetQotGyBsgAbA/hEdjtH3ntFUSz/mhlFyVC
i5g1aRcQq+6oOVVlPc1yqZWTEg4aSiYyf6W01A+fFxYFyFT5shcjB0ydBZrOChC7
NeZ7g1cCgYALZCIgxRdG+XkPzJcFN2LttQ9MdSDCLaaKEjDXGszZPNWrIhszPo/N
sF5NFrawTlG2zV4AmjpwnAjeb93qmoJpORHYM62EAOuvEzYOmCjtLCmOy6ICAukQ
1+YrZHbJ5ZQivi3W/PRCFSAZ0T4HrSvTK2gQHBPIVpYBZa4LbW+zmQKBgQCwbvtb
38U6OLrgFg4E0vF9lyZFfPZGMya8lZSGiw0a/zO8lDMXUiasorAZDmcRF1GSiZ//
VoekBLAE+C++RQKHiPthF/1WaHrm9yz88K3voQld/MZpuyYiXqBxfv3kjvrU5lgj
e/JJtyRBXS4zBf2c+oE/fxsQGV41D6ijkbSMRQKBgHiEF8okAzlkxopPUql4JVQM
t3kLS+9EzVg9izmOY4h1n5LkqNjHBGcUBohjI8vY/TBpqmb/xe1gR41GZVMsxXBQ
ClNv3gj8IdT951MAtT+5Bi1CwH74YkxCjqihkpwcBfLpSdSEQRpTma8MFfcQAXji
iOionhOeg/oWsiSXp9OQ
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
          body: 'signed.jwt.token'
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

      expect(mockBuilder.withSigningKey).toHaveBeenCalledWith(
        mockContext.secrets.SSF_KEY,
        mockContext.secrets.SSF_KEY_ID,
        'RS384'
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