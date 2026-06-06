// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! OpenAPI specification generator for the Issuer Service API.
//! Builds the OAS 3.1.0 document on demand from the runtime types using
//! `schemars`. Internal and admin paths are stripped from the public spec
//! by `strip_private_paths`.

use schemars::{schema_for, JsonSchema};
use serde_json::{json, Value};
use worker::Response;

// Concrete request and response types for the OpenAPI spec.
use crate::types::{
    BlindIssuanceResponse, ChallengeRequest, ChallengeResponse, CreateAttestationRequest,
    CreateAttestationResponse,
};

// Representation of a structured error response.
// Must mirror the actual `ErrorBody` struct in error.rs.
#[derive(serde::Serialize, JsonSchema)]
struct ErrorResponse {
    error: String,
    code: Option<String>,
}

/// Generate the complete OpenAPI specification at runtime from actual types.
pub fn generate_spec(version: &str, base_url: &str) -> Value {
    // Derive JSON schemas from the Rust types.
    let attestation_request_schema = schema_for!(CreateAttestationRequest);
    let attestation_response_schema = schema_for!(CreateAttestationResponse);
    let blind_issuance_response_schema = schema_for!(BlindIssuanceResponse);
    let error_response_schema = schema_for!(ErrorResponse);
    let challenge_request_schema = schema_for!(ChallengeRequest);
    let challenge_response_schema = schema_for!(ChallengeResponse);
    // Convert schemas into JSON values.
    let attestation_request_json =
        serde_json::to_value(&attestation_request_schema).unwrap_or(json!({}));
    let attestation_response_json =
        serde_json::to_value(&attestation_response_schema).unwrap_or(json!({}));
    let blind_issuance_response_json =
        serde_json::to_value(&blind_issuance_response_schema).unwrap_or(json!({}));
    let error_response_json = serde_json::to_value(&error_response_schema).unwrap_or(json!({}));
    let challenge_request_json =
        serde_json::to_value(&challenge_request_schema).unwrap_or(json!({}));
    let challenge_response_json =
        serde_json::to_value(&challenge_response_schema).unwrap_or(json!({}));
    // Remove metadata fields and extract the schema definitions.
    let extract_schema = |mut schema_json: Value| -> Value {
        if let Some(obj) = schema_json.as_object_mut() {
            obj.remove("$schema");
            obj.remove("title");
            json!(obj)
        } else {
            schema_json
        }
    };

    let all_definitions = json!({
        "CreateAttestationRequest": extract_schema(attestation_request_json.clone()),
        "CreateAttestationResponse": extract_schema(attestation_response_json.clone()),
        "BlindIssuanceResponse": extract_schema(blind_issuance_response_json.clone()),
        "ErrorResponse": extract_schema(error_response_json.clone()),
        "ChallengeRequest": extract_schema(challenge_request_json.clone()),
        "ChallengeResponse": extract_schema(challenge_response_json.clone()),
        "KeyRotationResponse": {
            "type": "object",
            "required": ["success", "version", "key_id", "created_at", "expires_at", "days_until_expiration"],
            "properties": {
                "success": { "type": "boolean" },
                "version": { "type": "integer", "description": "Key version number" },
                "key_id": { "type": "string", "description": "ID of the newly rotated key" },
                "created_at": { "type": "string", "description": "ISO 8601 creation timestamp" },
                "expires_at": { "type": "string", "description": "ISO 8601 expiration timestamp" },
                "days_until_expiration": { "type": "integer", "description": "Days remaining until the key expires" }
            }
        },
        "KeyHealthResponse": {
            "type": "object",
            "required": ["healthy", "critical", "has_expired_active", "has_expiring_soon", "has_no_keys", "has_no_active", "has_multiple_active", "days_until_expiration", "total_keys", "keys"],
            "properties": {
                "healthy": { "type": "boolean", "description": "Overall health assessment" },
                "critical": { "type": "boolean", "description": "Whether any critical issues exist" },
                "has_expired_active": { "type": "boolean" },
                "has_expiring_soon": { "type": "boolean" },
                "has_no_keys": { "type": "boolean" },
                "has_no_active": { "type": "boolean" },
                "has_multiple_active": { "type": "boolean" },
                // OAS 3.1: nullable integer uses a JSON Schema type union.
                "days_until_expiration": { "type": ["integer", "null"] },
                "total_keys": { "type": "integer", "description": "Total number of signing keys" },
                "keys": {
                    "type": "array",
                    "description": "Per-key status details",
                    "items": {
                        "type": "object",
                        "properties": {
                            "version": { "type": "integer" },
                            "key_id": { "type": "string" },
                            "status": { "type": "string" },
                            "created_at": { "type": "string" },
                            "expires_at": { "type": "string" },
                            "days_until_expiration": { "type": "integer" },
                            "is_expired": { "type": "boolean" },
                            "is_expiring_soon": { "type": "boolean" }
                        }
                    }
                }
            }
        }
    });

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Provii Issuer Service API",
            "version": version,
            "description": "Privacy-preserving credential issuance service using blind attestation. Officers create attestations that users scan to receive credentials without revealing commitment data.",
            "contact": {
                "name": "Provii Support",
                "email": "support@provii.app",
                "url": "https://provii.app"
            }
        },
        "servers": [
            {
                "url": base_url,
                "description": "Production server"
            }
        ],
        "tags": [
            {
                "name": "Attestation",
                "description": "Blind attestation creation for officers and clients"
            },
            {
                "name": "Issuance",
                "description": "Blind credential issuance for wallet users"
            },
            {
                "name": "Internal",
                "description": "Service-to-service endpoints (not for external callers)"
            },
            {
                "name": "Admin",
                "description": "Administrative endpoints (requires admin API key)"
            },
            {
                "name": "JWKS",
                "description": "JSON Web Key Set endpoints"
            },
            {
                "name": "Meta",
                "description": "API documentation endpoints"
            },
            {
                "name": "Operations",
                "description": "Health checks, metrics, and monitoring"
            }
        ],
        "paths": {
            "/v1/attestation/create": {
                "post": {
                    "summary": "Create blind attestation",
                    "description": "Creates a signed attestation containing dob_days that officers display as a QR code. Users scan this QR code and call /v1/issuance/blind to receive their credential.",
                    "operationId": "createAttestation",
                    "tags": ["Attestation"],
                    "security": [{ "ApiKeyAuth": [] }],
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "API key issued to the issuing organization"
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": attestation_request_json
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Attestation created successfully",
                            "content": {
                                "application/json": {
                                    "schema": attestation_response_json
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorized",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "403": {
                            "description": "Forbidden - invalid API key",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "429": {
                            "description": "Rate limit exceeded",
                            "headers": {
                                "Retry-After": {
                                    "schema": { "type": "integer" },
                                    "description": "Seconds until the rate limit resets"
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "503": {
                            "description": "Service unavailable - rate limiting infrastructure unavailable",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/issuance/blind": {
                "post": {
                    "summary": "Blind credential issuance",
                    "description": "Issues a credential using blind attestation. The user provides an attestation (from QR scan) and generates r_bits locally, ensuring the officer never sees the commitment C.\n\n**Forward-compatibility policy:** the request envelope does not apply `additionalProperties: false`. Unknown top-level fields are silently dropped on the server so future envelope additions roll out without a wire-format break. Field-level validation (length caps, base64 charset, schema URL form) is enforced individually via the `attestation`, `r_bits`, `schema`, and `validity_days` constraints below; the `validate` attributes on the Rust `BlindIssuanceRequest` type are the source of truth.",
                    "operationId": "blindIssuance",
                    "tags": ["Issuance"],
                    "security": [],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["attestation", "r_bits"],
                                    "additionalProperties": true,
                                    "description": "Forward-compatible envelope. `additionalProperties: true` documents the intentional omission of `serde(deny_unknown_fields)` on the Rust type so new fields can land without breaking existing clients.",
                                    "properties": {
                                        "attestation": {
                                            "type": "string",
                                            "description": "Base64url-encoded attestation from QR code",
                                            "maxLength": 1000
                                        },
                                        "r_bits": {
                                            "type": "string",
                                            "description": "Base64url-encoded random bits for commitment blinding (generated by wallet)",
                                            "maxLength": 64
                                        },
                                        "schema": {
                                            "type": "string",
                                            "description": "Optional schema URL override. Defaults to provii.age/0.",
                                            "maxLength": 500
                                        },
                                        "validity_days": {
                                            "type": "integer",
                                            "description": "Optional credential validity in days, bounded by issuer policy. Defaults to 36500 (lifetime).",
                                            "minimum": 1,
                                            "maximum": 36500
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Credential issued successfully",
                            "content": {
                                "application/json": {
                                    "schema": blind_issuance_response_json
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request - invalid attestation or r_bits",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "403": {
                            "description": "Forbidden - issuer mismatch, no eligible key, or attestation verification failed",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "409": {
                            "description": "Conflict - attestation nonce already used",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "429": {
                            "description": "Rate limit exceeded",
                            "headers": {
                                "Retry-After": {
                                    "schema": { "type": "integer" },
                                    "description": "Seconds until the rate limit resets"
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "503": {
                            "description": "Service unavailable - rate limiting infrastructure unavailable",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/jwks.json": {
                "get": {
                    "summary": "Get JWKS (redirect)",
                    "description": "Redirects to the canonical /.well-known/jwks.json location with a 301 Moved Permanently response.",
                    "operationId": "getJwksRedirect",
                    "tags": ["JWKS"],
                    "security": [],
                    "responses": {
                        "301": {
                            "description": "Moved Permanently to /.well-known/jwks.json",
                            "headers": {
                                "Location": {
                                    "schema": { "type": "string", "example": "/.well-known/jwks.json" },
                                    "description": "Canonical JWKS location"
                                }
                            }
                        }
                    }
                }
            },
            "/health": {
                "get": {
                    "summary": "Health check",
                    "operationId": "health",
                    "tags": ["Operations"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": { "type": "string", "example": "healthy", "enum": ["healthy", "degraded", "unhealthy"] },
                                            "timestamp": { "type": "integer", "format": "int64" },
                                            "version": { "type": "string" },
                                            "checks": { "type": "object", "description": "Subsystem health checks" }
                                        },
                                        "required": ["status", "timestamp", "version"]
                                    }
                                }
                            }
                        },
                        "503": {
                            "description": "Service unhealthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": { "type": "string", "example": "unhealthy", "enum": ["healthy", "degraded", "unhealthy"] },
                                            "timestamp": { "type": "integer", "format": "int64" },
                                            "version": { "type": "string" },
                                            "checks": { "type": "object", "description": "Subsystem health checks" }
                                        },
                                        "required": ["status", "timestamp", "version"]
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/health/detailed": {
                "get": {
                    "summary": "Detailed health check",
                    "description": "Returns detailed subsystem health checks including KV storage probes, configuration availability, and Durable Object connectivity. Requires authentication via Authorization: Bearer header.",
                    "operationId": "healthDetailed",
                    "tags": ["Operations"],
                    "security": [{ "StatusTokenAuth": [] }],
                    "parameters": [
                        {
                            "name": "Authorization",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Bearer token for authenticated health checks (Authorization: Bearer <token>)"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Detailed health status with subsystem checks",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": { "type": "string", "example": "healthy", "enum": ["healthy", "degraded", "unhealthy"] },
                                            "timestamp": { "type": "integer", "format": "int64" },
                                            "version": { "type": "string" },
                                            "checks": { "type": "object", "description": "Subsystem health checks with KV, config, and DO probe results" }
                                        },
                                        "required": ["status", "timestamp", "version", "checks"]
                                    }
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorised - missing or invalid Authorization header",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "503": {
                            "description": "Service unhealthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": { "type": "string", "example": "unhealthy", "enum": ["healthy", "degraded", "unhealthy"] },
                                            "timestamp": { "type": "integer", "format": "int64" },
                                            "version": { "type": "string" },
                                            "checks": { "type": "object" }
                                        },
                                        "required": ["status", "timestamp", "version", "checks"]
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "summary": "Service metrics",
                    "description": "Returns service metrics as JSON (same payload as /health/detailed). Requires authentication via Authorization: Bearer header.",
                    "operationId": "metrics",
                    "tags": ["Operations"],
                    "security": [{ "StatusTokenAuth": [] }],
                    "parameters": [
                        {
                            "name": "Authorization",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Bearer token for metrics access (Authorization: Bearer <token>)"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Service metrics",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": { "type": "string", "enum": ["healthy", "degraded", "unhealthy"] },
                                            "timestamp": { "type": "integer", "format": "int64" },
                                            "version": { "type": "string" },
                                            "checks": { "type": "object" }
                                        },
                                        "required": ["status", "timestamp", "version", "checks"]
                                    }
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorised - missing or invalid Authorization header",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/challenge": {
                "post": {
                    "summary": "Create officer challenge",
                    "description": "Creates a HMAC-SHA1 challenge for YubiKey officer authentication. The officer must respond with the correct HMAC to prove possession of the YubiKey.",
                    "operationId": "createOfficerChallenge",
                    "tags": ["Issuance"],
                    "security": [{ "YubiKeyHMAC": [] }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": challenge_request_json
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Challenge created",
                            "content": {
                                "application/json": {
                                    "schema": challenge_response_json
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorized",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "429": {
                            "description": "Rate limit exceeded",
                            "headers": {
                                "Retry-After": {
                                    "schema": { "type": "integer" },
                                    "description": "Seconds until the rate limit resets"
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "503": {
                            "description": "Service unavailable - rate limiting or authentication infrastructure unavailable",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/.well-known/jwks.json": {
                "get": {
                    "summary": "Get JWKS (well-known)",
                    "description": "Returns the issuer's public signing keys in JWKS format at the standard well-known URI",
                    "operationId": "getJwksWellKnown",
                    "tags": ["JWKS"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "JWKS returned successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "keys": {
                                                "type": "array",
                                                "items": { "type": "object" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/admin/keys/rotate": {
                "post": {
                    "summary": "Rotate signing keys",
                    "description": "Generates a new signing key pair, deprecates the current active key, and updates the JWKS. Requires admin authentication via Authorization: Bearer header and a single-use X-Nonce header.",
                    "operationId": "rotateKeys",
                    "tags": ["Admin"],
                    "security": [{ "AdminApiKey": [] }],
                    "parameters": [
                        {
                            "name": "Authorization",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Bearer token for admin key management (Authorization: Bearer <token>)"
                        },
                        {
                            "name": "X-Nonce",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Single-use nonce consumed against NonceDO to block replay."
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Key rotation successful",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/KeyRotationResponse" }
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorized - invalid admin key",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "429": {
                            "description": "Rate limit exceeded",
                            "headers": {
                                "Retry-After": {
                                    "schema": { "type": "integer" },
                                    "description": "Seconds until the rate limit resets"
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/admin/attestation-keys/rotate": {
                "post": {
                    "summary": "Rotate Ed25519 attestation signing key",
                    "description": "Promotes a pre-loaded Ed25519 attestation `kid` into `IssuerConfig.default_kid`, pushing the outgoing `kid` into `previous_kid` so trial-verify keeps both keys in scope during the overlap window. Both verifying and signing records for `new_kid` must already exist in their respective KV namespaces (out-of-band tooling step). Self-rotation is rejected.\n\nRequires admin API key authentication and a fresh `X-Nonce` header.",
                    "operationId": "rotateAttestationKeys",
                    "tags": ["Admin"],
                    "security": [{ "AdminApiKey": [] }],
                    "parameters": [
                        {
                            "name": "Authorization",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Bearer token for admin authentication (Authorization: Bearer <token>)"
                        },
                        {
                            "name": "X-Nonce",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Single-use nonce consumed against NonceDO to block replay."
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["new_kid"],
                                    "properties": {
                                        "new_kid": {
                                            "type": "string",
                                            "description": "Target kid to promote into default_kid. Must already have both verifying and signing records loaded in their KV namespaces."
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Attestation key rotation successful",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["success", "old_default_kid", "new_default_kid"],
                                        "properties": {
                                            "success": { "type": "boolean" },
                                            "old_default_kid": { "type": "string" },
                                            "new_default_kid": { "type": "string" },
                                            "previous_kid": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request (self-rotation, missing key material, or malformed kid)",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorised (missing credential, missing nonce, or replayed nonce)",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "429": {
                            "description": "Rate limit exceeded",
                            "headers": {
                                "Retry-After": {
                                    "schema": { "type": "integer" },
                                    "description": "Seconds until the rate limit resets"
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/admin/keys/health": {
                "get": {
                    "summary": "Check key health",
                    "description": "Returns the health status of signing keys including expiration warnings and configuration issues. Requires admin authentication via Authorization: Bearer header.",
                    "operationId": "keyHealth",
                    "tags": ["Admin"],
                    "security": [{ "AdminApiKey": [] }],
                    "parameters": [
                        {
                            "name": "Authorization",
                            "in": "header",
                            "required": true,
                            "schema": { "type": "string" },
                            "description": "Bearer token for admin key management (Authorization: Bearer <token>)"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Key health status",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/KeyHealthResponse" }
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorized",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "429": {
                            "description": "Rate limit exceeded",
                            "headers": {
                                "Retry-After": {
                                    "schema": { "type": "integer" },
                                    "description": "Seconds until the rate limit resets"
                                }
                            },
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "500": {
                            "description": "Internal server error",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/openapi.json": {
                "get": {
                    "summary": "OpenAPI specification",
                    "description": "Returns this OpenAPI specification document",
                    "operationId": "openapiSpec",
                    "tags": ["Meta"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "OpenAPI 3.1.0 specification",
                            "content": {
                                "application/json": {
                                    "schema": { "type": "object" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/docs": {
                "get": {
                    "summary": "API documentation",
                    "description": "Interactive API documentation rendered from the OpenAPI specification",
                    "operationId": "apiDocs",
                    "tags": ["Meta"],
                    "security": [],
                    "responses": {
                        "200": {
                            "description": "HTML documentation page",
                            "content": {
                                "text/html": {
                                    "schema": { "type": "string" }
                                }
                            }
                        }
                    }
                }
            },
            "/v1/register-test-issuer": {
                "x-sandbox-only": true,
                "post": {
                    "summary": "Register a test issuer (sandbox only)",
                    "description": "Creates a test issuer for sandbox integration testing. Only available in the sandbox environment.",
                    "operationId": "registerTestIssuer",
                    "tags": ["Internal"],
                    "security": [{ "AdminApiKey": [] }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["issuer_id", "schema_url"],
                                    "properties": {
                                        "issuer_id": {
                                            "type": "string",
                                            "description": "Unique identifier for the test issuer"
                                        },
                                        "schema_url": {
                                            "type": "string",
                                            "description": "Schema URL the test issuer will issue against"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Test issuer registered",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "issuer_id": { "type": "string" },
                                            "api_key": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Bad request",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        },
                        "403": {
                            "description": "Forbidden (not in sandbox environment)",
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": all_definitions,
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key issued to authorised issuing organisations"
                },
                "AdminApiKey": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Admin API key for key management operations (Authorization: Bearer <token>)"
                },
                "HmacAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-HMAC",
                    "description": "HMAC-SHA256 request signature for service-to-service calls"
                },
                "YubiKeyHMAC": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "HMAC-SHA1",
                    "description": "HMAC-SHA1 challenge-response authentication"
                },
                "StatusTokenAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "Dedicated token for health/metrics endpoint access (Authorization: Bearer <token>)"
                }
            }
        }
    })
}

/// Recursively remove `$schema` keys injected by schemars. OpenAPI 3.1
/// derives the JSON Schema dialect from the top-level `jsonSchemaDialect`,
/// so per-schema `$schema` keys are redundant noise.
fn strip_schema_keyword(val: &mut Value) {
    match val {
        Value::Object(map) => {
            map.remove("$schema");
            for v in map.values_mut() {
                strip_schema_keyword(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                strip_schema_keyword(v);
            }
        }
        _ => {}
    }
}

/// Tags whose paths should be stripped from the public spec.
const PRIVATE_TAGS: &[&str] = &["Internal", "Admin"];

/// Remove paths tagged as internal or admin from the spec. Prevents
/// information leakage about service-to-service and admin APIs.
fn strip_private_paths(mut spec: Value) -> Value {
    if let Some(paths) = spec.get_mut("paths").and_then(|p| p.as_object_mut()) {
        paths.retain(|_path, methods| {
            if let Some(obj) = methods.as_object() {
                !obj.values().any(|method| {
                    method
                        .get("tags")
                        .and_then(|t| t.as_array())
                        .map(|tags| {
                            tags.iter().any(|t| {
                                t.as_str()
                                    .map(|s| PRIVATE_TAGS.contains(&s))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false)
                })
            } else {
                true
            }
        });
    }
    spec
}

/// Serve the OpenAPI specification.
pub fn serve_openapi_json(version: &str, base_url: &str) -> worker::Result<Response> {
    let mut spec = strip_private_paths(generate_spec(version, base_url));
    strip_schema_keyword(&mut spec);

    let mut response = Response::from_json(&spec)?;

    let headers = response.headers_mut();
    headers.set("Content-Type", "application/json; charset=utf-8")?;
    headers.set("Cache-Control", "public, max-age=3600")?;
    // SECURITY: No wildcard CORS on API spec (O-3).
    headers.set("X-Content-Type-Options", "nosniff")?;

    Ok(response)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_spec_openapi_version() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        assert_eq!(spec["openapi"], "3.1.0");
    }

    #[test]
    fn test_generate_spec_info_section() {
        let spec = generate_spec("2.1.0", "https://api.example.com");
        assert_eq!(spec["info"]["title"], "Provii Issuer Service API");
        assert_eq!(spec["info"]["version"], "2.1.0");
    }

    #[test]
    fn test_generate_spec_attestation_endpoint() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/attestation/create"]["post"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "createAttestation");
    }

    #[test]
    fn test_generate_spec_blind_issuance_endpoint() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/issuance/blind"]["post"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "blindIssuance");
    }

    /// Forward-compatibility policy on `BlindIssuanceRequest` is documented
    /// in the OpenAPI request body schema. The Rust type intentionally omits
    /// `serde(deny_unknown_fields)` so unknown top-level fields are silently
    /// dropped instead of failing the wire format break. This test pins the
    /// `additionalProperties: true` marker and the explanatory description
    /// so a future refactor that flips either back to `false` is caught at
    /// build time, before it can ship a breaking change to wallet clients.
    #[test]
    fn test_blind_issuance_schema_documents_forward_compat_policy() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schema = &spec["paths"]["/v1/issuance/blind"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"];
        assert_eq!(
            schema["additionalProperties"],
            serde_json::Value::Bool(true)
        );
        let desc = schema["description"].as_str().unwrap_or_default();
        assert!(
            desc.contains("deny_unknown_fields"),
            "schema description must reference deny_unknown_fields policy, got {:?}",
            desc
        );
    }

    /// Pin the attestation rotation endpoint shape so a refactor that
    /// drops `previous_kid` or the `old_default_kid` observable is caught
    /// at build time. Both fields are required for trial-verify diagnostics.
    #[test]
    fn test_generate_spec_attestation_rotate_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/admin/attestation-keys/rotate"]["post"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "rotateAttestationKeys");
        assert!(path["tags"]
            .as_array()
            .ok_or("expected array")?
            .contains(&serde_json::json!("Admin")));
        let resp200 = &path["responses"]["200"]["content"]["application/json"]["schema"];
        let required = resp200["required"]
            .as_array()
            .ok_or("expected required array")?;
        assert!(required.contains(&serde_json::json!("old_default_kid")));
        assert!(required.contains(&serde_json::json!("new_default_kid")));
        Ok(())
    }

    #[test]
    fn test_generate_spec_jwks_endpoint() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/jwks.json"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "getJwksRedirect");
    }

    #[test]
    fn test_generate_spec_health_endpoint() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/health"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "health");
    }

    #[test]
    fn test_generate_spec_challenge_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/challenge"]["post"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "createOfficerChallenge");
        assert!(path["tags"]
            .as_array()
            .ok_or("expected array")?
            .contains(&serde_json::json!("Issuance")));
        Ok(())
    }

    #[test]
    fn test_generate_spec_well_known_jwks_endpoint() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/.well-known/jwks.json"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "getJwksWellKnown");
    }

    #[test]
    fn test_generate_spec_keys_rotate_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/admin/keys/rotate"]["post"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "rotateKeys");
        assert!(path["tags"]
            .as_array()
            .ok_or("expected array")?
            .contains(&serde_json::json!("Admin")));
        Ok(())
    }

    #[test]
    fn test_generate_spec_keys_health_endpoint() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/admin/keys/health"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "keyHealth");
    }

    #[test]
    fn test_generate_spec_openapi_json_endpoint() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/openapi.json"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "openapiSpec");
    }

    #[test]
    fn test_generate_spec_docs_endpoint() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let path = &spec["paths"]["/v1/docs"]["get"];
        assert!(path.is_object());
        assert_eq!(path["operationId"], "apiDocs");
    }

    #[test]
    fn test_strip_private_paths_removes_internal_admin() {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let stripped = strip_private_paths(spec);
        let paths = stripped["paths"].as_object().expect("paths object");
        assert!(!paths.contains_key("/v1/admin/keys/rotate"));
        assert!(!paths.contains_key("/v1/admin/keys/health"));
        assert!(!paths.contains_key("/v1/admin/attestation-keys/rotate"));
    }

    #[test]
    fn test_generate_spec_paths_count() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let paths = spec["paths"].as_object().ok_or("expected object")?;
        // 14 paths after removing session-based issuance endpoints and
        // the `/v1/issuers/{kid}/config` lookup; bound matches the actual
        // path count so accidental removals are caught.
        assert!(paths.len() >= 14);
        Ok(())
    }

    #[test]
    fn test_generate_spec_tags_count() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let tags = spec["tags"].as_array().ok_or("expected array")?;
        // Attestation, Issuance, Internal, Admin, JWKS, Meta, Operations.
        assert_eq!(tags.len(), 7);
        Ok(())
    }

    #[test]
    fn test_generate_spec_has_expected_schemas() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schemas = spec["components"]["schemas"]
            .as_object()
            .ok_or("expected object")?;
        assert!(schemas.contains_key("ChallengeRequest"));
        assert!(schemas.contains_key("ChallengeResponse"));
        assert!(schemas.contains_key("KeyRotationResponse"));
        assert!(schemas.contains_key("KeyHealthResponse"));
        // `StartRequest`/`StartResponse` and `IssuerRoyaltyConfig` are
        // intentionally absent. These types are not exposed in the public API.
        assert!(!schemas.contains_key("StartRequest"));
        assert!(!schemas.contains_key("StartResponse"));
        assert!(!schemas.contains_key("IssuerRoyaltyConfig"));
        Ok(())
    }

    #[test]
    fn test_generate_spec_has_security_schemes() -> Result<(), Box<dyn std::error::Error>> {
        let spec = generate_spec("1.0.0", "https://api.example.com");
        let schemes = spec["components"]["securitySchemes"]
            .as_object()
            .ok_or("expected object")?;
        assert!(schemes.contains_key("ApiKeyAuth"));
        assert!(schemes.contains_key("AdminApiKey"));
        assert!(schemes.contains_key("HmacAuth"));
        assert!(schemes.contains_key("YubiKeyHMAC"));
        Ok(())
    }

    /// Regenerates `openapi/openapi.json` from the runtime generator. The
    /// `publish-openapi.yml` workflow `cp`s this file into the signed R2
    /// artefact, which the docs proxy and external consumers fetch. The
    /// snapshot MUST match what `serve_openapi_json` returns on the wire,
    /// which means applying both `strip_private_paths` (drops Internal +
    /// Admin tagged paths) and `strip_schema_keyword` (drops redundant
    /// per-schema `$schema` keys). Without these, the published spec
    /// leaks admin endpoints and includes JSON Schema noise that diverges
    /// from the live worker.
    ///
    /// To regenerate:
    ///
    ///     UPDATE_OPENAPI_SNAPSHOT=1 cargo test --lib \
    ///       --target aarch64-apple-darwin \
    ///       openapi::tests::regen_openapi_snapshot
    ///
    /// Native target only because `std::fs` is unavailable on
    /// `wasm32-unknown-unknown`. No-op without the env flag so default
    /// `cargo test` runs do not mutate the working tree.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn regen_openapi_snapshot() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os("UPDATE_OPENAPI_SNAPSHOT").is_none() {
            return Ok(());
        }
        // Production values from `wrangler.toml` (top-level [vars]).
        let version = "1.0.0";
        let base_url = "https://issuer.provii.app";

        // Apply the SAME transforms as `serve_openapi_json` so the on-disk
        // snapshot matches the wire bytes byte-for-byte.
        let mut spec = strip_private_paths(generate_spec(version, base_url));
        strip_schema_keyword(&mut spec);

        // Match the existing on-disk format: 4-space indent, trailing newline.
        let mut buf = Vec::with_capacity(64 * 1024);
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
        serde::Serialize::serialize(&spec, &mut ser)?;
        buf.push(b'\n');

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let target = std::path::Path::new(manifest_dir).join("openapi/openapi.json");
        std::fs::write(&target, &buf)?;
        Ok(())
    }
}
