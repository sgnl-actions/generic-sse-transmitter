# Generic SSE Transmitter

Transmits Security Event Tokens (SET) for CAEP (Continuous Access Evaluation Protocol) and other security events to specified endpoints.

## Overview

This action creates, signs, and transmits Security Event Tokens (SETs) according to the [RFC 8417](https://datatracker.ietf.org/doc/html/rfc8417) specification. It supports both CAEP events (session revoked, credential change, etc.) and custom security events.

## Prerequisites

- RSA private key for JWT signing (PEM format)
- SET receiver endpoint URL
- Optional: Bearer token for receiver authentication

## Configuration

### Secrets

| Name | Description | Required |
|------|-------------|----------|
| `SSF_KEY` | RSA private key in PEM format for signing JWTs | Yes |
| `SSF_KEY_ID` | Key identifier to include in JWT header | Yes |
| `AUTH_TOKEN` | Bearer token for authenticating with SET receiver | No |

### Inputs

| Name | Type | Description | Required |
|------|------|-------------|----------|
| `type` | string | Security event type URI (e.g., `https://schemas.openid.net/secevent/caep/event-type/session-revoked`) | Yes |
| `audience` | string | Intended recipient of the SET (e.g., `https://customer.okta.com/`) | Yes |
| `subject` | string | JSON string representing the subject (simple or complex format) | Yes |
| `eventPayload` | object | Event-specific payload data | Yes |
| `address` | string | Destination URL for the SET transmission | No* |
| `addressSuffix` | string | Optional suffix to append to the address | No |
| `customClaims` | object | Custom claims to add to the JWT root | No |
| `subjectFormat` | string | Subject format: `SubjectInEventClaims` or `SubjectInSubId` (default) | No |
| `issuer` | string | JWT issuer identifier (default: `https://sgnl.ai/`) | No |
| `signingMethod` | string | JWT signing algorithm (default: `RS256`) | No |

*Note: Either `address` must be provided or `SET_RECEIVER_URL` environment variable must be set.

### Outputs

| Name | Type | Description |
|------|------|-------------|
| `status` | string | Operation result: `success` or `failed` |
| `statusCode` | number | HTTP status code from the SET receiver |
| `body` | string | Response body from the SET receiver |

## Subject Formats

### Simple Subject
```json
{
  "format": "email",
  "email": "user@example.com"
}
```

### Complex Subject
```json
{
  "user": {
    "format": "email",
    "email": "user@example.com"
  },
  "session": {
    "format": "opaque",
    "id": "session-123"
  }
}
```

## Usage Examples

### Basic Session Revoked Event

```json
{
  "type": "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
  "audience": "https://customer.okta.com/",
  "subject": "{\"format\":\"email\",\"email\":\"user@example.com\"}",
  "eventPayload": {
    "initiating_entity": "policy",
    "reason_user": "Session terminated due to policy violation",
    "reason_admin": "Landspeed Policy Violation: C076E82F"
  },
  "address": "https://receiver.example.com/events"
}
```

### Token Claims Change Event

```json
{
  "type": "https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
  "audience": "https://app.example.com/",
  "subject": "{\"format\":\"opaque\",\"id\":\"user-123\"}",
  "eventPayload": {
    "claims": {
      "groups": ["admin", "users"],
      "department": "engineering"
    }
  },
  "address": "https://receiver.example.com/events"
}
```

### Custom Event with Complex Subject

```json
{
  "type": "https://example.com/events/custom-risk-event",
  "audience": "https://security.example.com/",
  "subject": "{\"user\":{\"format\":\"email\",\"email\":\"user@example.com\"},\"device\":{\"format\":\"opaque\",\"id\":\"device-456\"}}",
  "eventPayload": {
    "risk_level": "high",
    "risk_factors": ["unusual_location", "new_device"]
  },
  "address": "https://receiver.example.com/security/events",
  "customClaims": {
    "tenant_id": "tenant-789",
    "policy_version": "2.0"
  }
}
```

## Error Handling

The action distinguishes between retryable and non-retryable errors:

### Retryable Errors (Framework will retry)
- `429` - Rate limited
- `502` - Bad gateway
- `503` - Service unavailable
- `504` - Gateway timeout

### Non-Retryable Errors (Fatal)
- `400` - Bad request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not found

## Security Considerations

1. **Private Key Security**: The RSA private key (`SSF_KEY`) should be stored securely and rotated regularly
2. **Key ID Management**: The `SSF_KEY_ID` should match the key registered with the SET receiver
3. **Bearer Token**: If the receiver requires authentication, ensure the `AUTH_TOKEN` is kept secure
4. **Subject PII**: Be mindful of personally identifiable information in subject fields
5. **Event Payload**: Avoid including sensitive data in event payloads unless necessary

## Supported Event Types

### CAEP Events
- `https://schemas.openid.net/secevent/caep/event-type/session-revoked`
- `https://schemas.openid.net/secevent/caep/event-type/token-claims-change`
- `https://schemas.openid.net/secevent/caep/event-type/credential-change`
- `https://schemas.openid.net/secevent/caep/event-type/assurance-level-change`
- `https://schemas.openid.net/secevent/caep/event-type/device-compliance-change`

### Custom Events
Any custom event type URI can be used as long as the receiver supports it.

## Troubleshooting

### Common Issues

1. **"SSF_KEY secret is required"**
   - Ensure the RSA private key is configured in secrets

2. **"Invalid subject JSON"**
   - Verify the subject parameter contains valid JSON
   - Check for proper escaping of quotes

3. **"SET transmission failed: 401 Unauthorized"**
   - Verify the AUTH_TOKEN is correct
   - Check if the receiver requires a specific token format

4. **"address parameter or SET_RECEIVER_URL environment variable is required"**
   - Provide either the `address` input parameter or set the `SET_RECEIVER_URL` environment variable

## Development

### Testing
```bash
npm test                 # Run tests
npm run test:coverage    # Check coverage
```

### Building
```bash
npm run build           # Build distribution
```

### Linting
```bash
npm run lint            # Check code style
npm run lint:fix        # Fix code style issues
```

## References

- [RFC 8417 - Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)
- [OpenID CAEP Specification](https://openid.net/specs/openid-caep-specification-1_0.html)
- [OpenID SSE Framework](https://openid.net/specs/openid-sse-framework-1_0.html)