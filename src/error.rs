// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error types shared across the issuer worker.

use serde::Serialize;
use thiserror::Error;
use worker::Error as WorkerError;
use worker::Response;

/// Structured JSON error body matching the OpenAPI `ErrorResponse` schema.
#[derive(Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

/// API-facing error variants that map to Worker responses.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("Worker error: {0}")]
    Worker(#[from] WorkerError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("Unsupported media type: {0}")]
    UnsupportedMediaType(String),

    #[error("Length required: {0}")]
    LengthRequired(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl ApiError {
    /// Convert this error into a structured JSON `Response`.
    ///
    /// Client-safe variants expose their message string.
    /// Internal variants sanitise to "Internal server error".
    /// Parse-error variants sanitise to generic 400 messages.
    pub fn to_response(self) -> std::result::Result<Response, WorkerError> {
        let (status, error_code, message) = match &self {
            // Client-safe variants: use generic messages to prevent information leakage.
            // Specific details are logged server-side only.
            ApiError::BadRequest(msg) => {
                // Curated allowlist of safe messages. Anything else gets a generic response.
                // The full message is logged server-side via the Display impl.
                let safe = match msg.as_str() {
                    "Missing required field"
                    | "Invalid request format"
                    | "Invalid identifier format"
                    | "Invalid encoding"
                    | "Payload too large"
                    | "Proof verification failed" => msg.clone(),
                    _ => "Invalid request".to_string(),
                };
                (400, "BAD_REQUEST", safe)
            }
            ApiError::NotFound(_) => (404, "NOT_FOUND", "Not found".to_string()),
            ApiError::Unauthorized(_) => {
                (401, "UNAUTHORIZED", "Authentication required".to_string())
            }
            ApiError::Forbidden(_) => (403, "FORBIDDEN", "Access denied".to_string()),
            ApiError::SessionExpired => (
                401,
                "SESSION_EXPIRED",
                "Authentication required".to_string(),
            ),
            ApiError::InvalidSignature(_) => (
                401,
                "INVALID_SIGNATURE",
                "Authentication required".to_string(),
            ),
            ApiError::InvalidProof(_) => (
                400,
                "INVALID_PROOF",
                "Proof verification failed".to_string(),
            ),
            ApiError::RateLimitExceeded => (
                429,
                "RATE_LIMIT_EXCEEDED",
                "Rate limit exceeded".to_string(),
            ),
            ApiError::Conflict(_) => (409, "CONFLICT", "Resource conflict".to_string()),
            ApiError::PayloadTooLarge(_) => {
                (413, "PAYLOAD_TOO_LARGE", "Payload too large".to_string())
            }
            ApiError::UnsupportedMediaType(_) => (
                415,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json".to_string(),
            ),
            ApiError::LengthRequired(_) => (411, "LENGTH_REQUIRED", "Length required".to_string()),
            ApiError::InvalidStateTransition(_) => (
                409,
                "INVALID_STATE_TRANSITION",
                "Invalid state transition".to_string(),
            ),
            // Internal: sanitise, never leak implementation details
            ApiError::CryptoError(_) => {
                (500, "INTERNAL_ERROR", "Internal server error".to_string())
            }
            ApiError::StorageError(_) => {
                (500, "INTERNAL_ERROR", "Internal server error".to_string())
            }
            ApiError::Worker(_) => (500, "INTERNAL_ERROR", "Internal server error".to_string()),
            ApiError::Json(_) => (400, "BAD_REQUEST", "Invalid request format".to_string()),
            ApiError::Uuid(_) => (400, "BAD_REQUEST", "Invalid identifier format".to_string()),
            ApiError::Base64(_) => (400, "BAD_REQUEST", "Invalid encoding".to_string()),
            ApiError::Internal(_) => (500, "INTERNAL_ERROR", "Internal server error".to_string()),
            ApiError::ServiceUnavailable(_) => (
                503,
                "SERVICE_UNAVAILABLE",
                "Service temporarily unavailable".to_string(),
            ),
        };

        let body = ErrorBody {
            error: message,
            code: Some(error_code.to_string()),
        };

        // Log internal errors server-side for debugging
        if status == 500 {
            crate::log_error!("[Error] {}: {:?}", error_code, self);
        }

        let mut response = Response::from_json(&body)?.with_status(status);

        // SECURITY: ASVS V4.1.1, explicit charset
        response
            .headers_mut()
            .set("Content-Type", "application/json; charset=utf-8")?;

        // SECURITY: ASVS V14.2.5, anti-caching on all error responses
        response.headers_mut().set(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, private",
        )?;
        response.headers_mut().set("Pragma", "no-cache")?;
        response.headers_mut().set("Expires", "0")?;

        // Retry-After for 503 responses (default 60 seconds)
        if status == 503 {
            response.headers_mut().set("Retry-After", "60")?;
        }

        // SECURITY: Clear-Site-Data for auth failures
        if matches!(
            self,
            ApiError::Unauthorized(_)
                | ApiError::Forbidden(_)
                | ApiError::SessionExpired
                | ApiError::InvalidSignature(_)
        ) {
            response
                .headers_mut()
                .set("Clear-Site-Data", r#""cache", "cookies", "storage""#)?;
        }

        Ok(response)
    }
}

/// Convenience alias for results that surface `ApiError`.
pub type Result<T> = std::result::Result<T, ApiError>;

impl From<ApiError> for WorkerError {
    fn from(err: ApiError) -> Self {
        // SECURITY: Never expose internal error details via WorkerError.
        // The Display impl may contain internal information (e.g. storage
        // paths, crypto details). Always use a generic message.
        match &err {
            ApiError::BadRequest(_) => WorkerError::from("Bad request".to_string()),
            ApiError::NotFound(_) => WorkerError::from("Not found".to_string()),
            ApiError::Unauthorized(_) => WorkerError::from("Unauthorized".to_string()),
            ApiError::Forbidden(_) => WorkerError::from("Forbidden".to_string()),
            ApiError::SessionExpired => WorkerError::from("Session expired".to_string()),
            ApiError::RateLimitExceeded => WorkerError::from("Rate limit exceeded".to_string()),
            ApiError::Conflict(_) => WorkerError::from("Conflict".to_string()),
            ApiError::PayloadTooLarge(_) => WorkerError::from("Payload too large".to_string()),
            ApiError::UnsupportedMediaType(_) => {
                WorkerError::from("Unsupported media type".to_string())
            }
            ApiError::LengthRequired(_) => WorkerError::from("Length required".to_string()),
            ApiError::InvalidStateTransition(_) => {
                WorkerError::from("Invalid state transition".to_string())
            }
            // All internal/crypto/parse errors get a generic message
            _ => WorkerError::from("Internal server error".to_string()),
        }
    }
}

impl From<issuer_logic::error::LogicError> for ApiError {
    fn from(err: issuer_logic::error::LogicError) -> Self {
        match err {
            issuer_logic::error::LogicError::BadRequest(msg) => ApiError::BadRequest(msg),
            issuer_logic::error::LogicError::CryptoError(msg) => ApiError::CryptoError(msg),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        // Log the full chain server-side, but store only a generic message
        // in the variant to prevent leaking internals via Display.
        crate::log_error!("[anyhow] {:#}", err);
        ApiError::Internal("Internal server error".to_string())
    }
}

impl From<provii_crypto_commons::Error> for ApiError {
    fn from(err: provii_crypto_commons::Error) -> Self {
        use provii_crypto_commons::Error;
        match err {
            Error::InvalidFormat => ApiError::BadRequest("Invalid format".to_string()),
            Error::InvalidInput => ApiError::BadRequest("Invalid input".to_string()),
            Error::InvalidSignature => ApiError::InvalidSignature("Invalid signature".to_string()),
            Error::VerificationFailed => ApiError::InvalidProof("Verification failed".to_string()),
            Error::InvalidProof => ApiError::InvalidProof("Invalid proof".to_string()),
            Error::Expired => ApiError::SessionExpired,
            Error::NotFound => ApiError::NotFound("Resource not found".to_string()),
            Error::RateLimitExceeded => ApiError::RateLimitExceeded,
            Error::InvalidOriginHash
            | Error::MissingTimestamp
            | Error::FutureTimestamp
            | Error::FieldTooLong => {
                crate::log_error!("[crypto-commons] {:?}", err);
                ApiError::BadRequest("Invalid request".to_string())
            }
            Error::CredentialBanned => {
                crate::log_error!("[crypto-commons] {:?}", err);
                ApiError::Forbidden("Credential banned".to_string())
            }
            Error::NullifierStoreFailure
            | Error::ProverFailed
            | Error::VerifierNotInitialized
            | Error::AlreadyInitialized
            | Error::Internal => {
                crate::log_error!("[crypto-commons] {:?}", err);
                ApiError::Internal("Cryptographic operation failed".to_string())
            }
        }
    }
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

    /* ========================================================================== */
    /*                    ApiError DISPLAY TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_bad_request_display() {
        let err = ApiError::BadRequest("missing field".to_string());
        assert_eq!(err.to_string(), "Invalid request: missing field");
    }

    #[test]
    fn test_not_found_display() {
        let err = ApiError::NotFound("session-123".to_string());
        assert_eq!(err.to_string(), "Not found: session-123");
    }

    #[test]
    fn test_unauthorized_display() {
        let err = ApiError::Unauthorized("invalid API key".to_string());
        assert_eq!(err.to_string(), "Unauthorized: invalid API key");
    }

    #[test]
    fn test_forbidden_display() {
        let err = ApiError::Forbidden("access denied".to_string());
        assert_eq!(err.to_string(), "Forbidden: access denied");
    }

    #[test]
    fn test_session_expired_display() {
        let err = ApiError::SessionExpired;
        assert_eq!(err.to_string(), "Session expired");
    }

    #[test]
    fn test_invalid_signature_display() {
        let err = ApiError::InvalidSignature("HMAC mismatch".to_string());
        assert_eq!(err.to_string(), "Invalid signature: HMAC mismatch");
    }

    #[test]
    fn test_invalid_proof_display() {
        let err = ApiError::InvalidProof("commitment mismatch".to_string());
        assert_eq!(err.to_string(), "Invalid proof: commitment mismatch");
    }

    #[test]
    fn test_crypto_error_display() {
        let err = ApiError::CryptoError("key generation failed".to_string());
        assert_eq!(err.to_string(), "Crypto error: key generation failed");
    }

    #[test]
    fn test_storage_error_display() {
        let err = ApiError::StorageError("KV put failed".to_string());
        assert_eq!(err.to_string(), "Storage error: KV put failed");
    }

    #[test]
    fn test_rate_limit_exceeded_display() {
        let err = ApiError::RateLimitExceeded;
        assert_eq!(err.to_string(), "Rate limit exceeded");
    }

    #[test]
    fn test_internal_display() {
        let err = ApiError::Internal("unexpected panic".to_string());
        assert_eq!(err.to_string(), "Internal error: unexpected panic");
    }

    #[test]
    fn test_json_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid")
            .err()
            .ok_or("expected error")?;
        let err = ApiError::Json(json_err);
        let msg = err.to_string();
        assert!(msg.starts_with("JSON error:"));
        Ok(())
    }

    #[test]
    fn test_uuid_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let uuid_err = uuid::Uuid::parse_str("invalid-uuid")
            .err()
            .ok_or("expected error")?;
        let err = ApiError::Uuid(uuid_err);
        let msg = err.to_string();
        assert!(msg.starts_with("UUID error:"));
        Ok(())
    }

    #[test]
    fn test_base64_error_display() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use base64::Engine;
        let b64_err = base64::engine::general_purpose::STANDARD
            .decode("!!!invalid!!!")
            .err()
            .ok_or("expected error")?;
        let err = ApiError::Base64(b64_err);
        let msg = err.to_string();
        assert!(msg.starts_with("Base64 error:"));
        Ok(())
    }

    /* ========================================================================== */
    /*                    ApiError VARIANT TESTS                                 */
    /* ========================================================================== */

    #[test]
    fn test_bad_request_empty_message() {
        let err = ApiError::BadRequest("".to_string());
        assert_eq!(err.to_string(), "Invalid request: ");
    }

    #[test]
    fn test_bad_request_special_chars() {
        let err = ApiError::BadRequest("field with 'quotes' and \"double quotes\"".to_string());
        assert!(err.to_string().contains("'quotes'"));
        assert!(err.to_string().contains("\"double quotes\""));
    }

    #[test]
    fn test_not_found_uuid_format() {
        let err = ApiError::NotFound("550e8400-e29b-41d4-a716-446655440000".to_string());
        assert!(err.to_string().contains("550e8400"));
    }

    #[test]
    fn test_unauthorized_empty_message() {
        let err = ApiError::Unauthorized("".to_string());
        assert_eq!(err.to_string(), "Unauthorized: ");
    }

    #[test]
    fn test_forbidden_long_message() {
        let msg = "a".repeat(500);
        let err = ApiError::Forbidden(msg.clone());
        assert!(err.to_string().contains(&msg));
    }

    #[test]
    fn test_invalid_signature_multiline() {
        let err = ApiError::InvalidSignature("line1\nline2\nline3".to_string());
        assert!(err.to_string().contains("line1"));
        assert!(err.to_string().contains("line3"));
    }

    #[test]
    fn test_invalid_proof_unicode() {
        let err = ApiError::InvalidProof("证明无效 🚫".to_string());
        assert!(err.to_string().contains("证明无效"));
        assert!(err.to_string().contains("🚫"));
    }

    #[test]
    fn test_crypto_error_hex_data() {
        let err = ApiError::CryptoError("0xDEADBEEF".to_string());
        assert!(err.to_string().contains("0xDEADBEEF"));
    }

    #[test]
    fn test_storage_error_json_message() {
        let err = ApiError::StorageError(r#"{"error":"timeout"}"#.to_string());
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_internal_stack_trace() {
        let err = ApiError::Internal("at line 42 in module.rs".to_string());
        assert!(err.to_string().contains("line 42"));
    }

    /* ========================================================================== */
    /*                    FROM TRAIT IMPLEMENTATION TESTS                        */
    /* ========================================================================== */

    #[test]
    fn test_from_json_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid")
            .err()
            .ok_or("expected error")?;
        let api_err: ApiError = json_err.into();
        assert!(matches!(api_err, ApiError::Json(_)));
        Ok(())
    }

    #[test]
    fn test_from_uuid_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let uuid_err = uuid::Uuid::parse_str("not-a-uuid")
            .err()
            .ok_or("expected error")?;
        let api_err: ApiError = uuid_err.into();
        assert!(matches!(api_err, ApiError::Uuid(_)));
        Ok(())
    }

    #[test]
    fn test_from_base64_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use base64::Engine;
        let b64_err = base64::engine::general_purpose::STANDARD
            .decode("!!!")
            .err()
            .ok_or("expected error")?;
        let api_err: ApiError = b64_err.into();
        assert!(matches!(api_err, ApiError::Base64(_)));
        Ok(())
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("something went wrong");
        let api_err: ApiError = anyhow_err.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
        // SECURITY: anyhow details are logged server-side, not stored in variant
        assert!(api_err.to_string().contains("Internal server error"));
    }

    #[test]
    fn test_from_crypto_invalid_format() {
        let crypto_err = provii_crypto_commons::Error::InvalidFormat;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::BadRequest(_)));
        assert_eq!(api_err.to_string(), "Invalid request: Invalid format");
    }

    #[test]
    fn test_from_crypto_invalid_signature() {
        let crypto_err = provii_crypto_commons::Error::InvalidSignature;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::InvalidSignature(_)));
        assert_eq!(api_err.to_string(), "Invalid signature: Invalid signature");
    }

    #[test]
    fn test_from_crypto_verification_failed() {
        let crypto_err = provii_crypto_commons::Error::VerificationFailed;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::InvalidProof(_)));
        assert_eq!(api_err.to_string(), "Invalid proof: Verification failed");
    }

    #[test]
    fn test_from_crypto_expired() {
        let crypto_err = provii_crypto_commons::Error::Expired;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::SessionExpired));
        assert_eq!(api_err.to_string(), "Session expired");
    }

    #[test]
    fn test_from_crypto_internal() {
        let crypto_err = provii_crypto_commons::Error::Internal;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
        // SECURITY: crypto details logged server-side, generic message in variant
        assert!(api_err
            .to_string()
            .contains("Cryptographic operation failed"));
    }

    #[test]
    fn test_into_worker_error() {
        let api_err = ApiError::BadRequest("test".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Bad request"));
    }

    #[test]
    fn test_into_worker_error_sanitises_message() {
        // SECURITY: WorkerError must NOT contain the original detail message
        let api_err = ApiError::Unauthorized("missing X-API-Key".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(!worker_err.to_string().contains("missing X-API-Key"));
        assert!(worker_err.to_string().contains("Unauthorized"));
    }

    /* ========================================================================== */
    /*                    RESULT TYPE ALIAS TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_result_ok() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result: Result<i32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result?, 42);
        Ok(())
    }

    #[test]
    fn test_result_err() {
        let result: Result<i32> = Err(ApiError::BadRequest("test".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_result_map() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result: Result<i32> = Ok(10);
        let mapped = result.map(|x| x * 2);
        assert_eq!(mapped?, 20);
        Ok(())
    }

    #[test]
    fn test_result_and_then() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let result: Result<i32> = Ok(5);
        let chained = result.map(|x| x + 10);
        assert_eq!(chained?, 15);
        Ok(())
    }

    /* ========================================================================== */
    /*                    DEBUG FORMAT TESTS                                     */
    /* ========================================================================== */

    #[test]
    fn test_debug_format_bad_request() {
        let err = ApiError::BadRequest("test".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("BadRequest"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_debug_format_session_expired() {
        let err = ApiError::SessionExpired;
        let debug = format!("{:?}", err);
        assert!(debug.contains("SessionExpired"));
    }

    #[test]
    fn test_debug_format_rate_limit() {
        let err = ApiError::RateLimitExceeded;
        let debug = format!("{:?}", err);
        assert!(debug.contains("RateLimitExceeded"));
    }

    #[test]
    fn test_invalid_state_transition_display() {
        let err = ApiError::InvalidStateTransition(
            "Cannot transition from Pending to Completed".to_string(),
        );
        assert_eq!(
            err.to_string(),
            "Invalid state transition: Cannot transition from Pending to Completed"
        );
    }

    #[test]
    fn test_debug_format_invalid_state_transition() {
        let err = ApiError::InvalidStateTransition("test transition".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidStateTransition"));
        assert!(debug.contains("test transition"));
    }

    /* ========================================================================== */
    /*                    ERROR CHAIN TESTS                                      */
    /* ========================================================================== */

    #[test]
    fn test_error_chain_json_to_worker_sanitised(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad")
            .err()
            .ok_or("expected error")?;
        let api_err: ApiError = json_err.into();
        let worker_err: WorkerError = api_err.into();
        // SECURITY: Must NOT contain JSON parse details
        assert!(worker_err.to_string().contains("Internal server error"));
        Ok(())
    }

    #[test]
    fn test_error_chain_uuid_to_worker_sanitised(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let uuid_err = uuid::Uuid::parse_str("malformed")
            .err()
            .ok_or("expected error")?;
        let api_err: ApiError = uuid_err.into();
        let worker_err: WorkerError = api_err.into();
        // SECURITY: Must NOT contain UUID parse details
        assert!(worker_err.to_string().contains("Internal server error"));
        Ok(())
    }

    #[test]
    fn test_error_chain_anyhow_to_worker_sanitised() {
        let anyhow_err = anyhow::anyhow!("custom error");
        let api_err: ApiError = anyhow_err.into();
        let worker_err: WorkerError = api_err.into();
        // SECURITY: Must NOT contain the original error message
        assert!(!worker_err.to_string().contains("custom error"));
        assert!(worker_err.to_string().contains("Internal server error"));
    }

    /* ========================================================================== */
    /*                    ERROR BODY SERIALIZATION TESTS                         */
    /* ========================================================================== */

    #[test]
    fn test_error_body_with_code() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "Something went wrong".to_string(),
            code: Some("BAD_REQUEST".to_string()),
        };
        let json = serde_json::to_value(&body)?;
        assert_eq!(json["error"], "Something went wrong");
        assert_eq!(json["code"], "BAD_REQUEST");
        Ok(())
    }

    #[test]
    fn test_error_body_without_code() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "Something went wrong".to_string(),
            code: None,
        };
        let json = serde_json::to_value(&body)?;
        assert_eq!(json["error"], "Something went wrong");
        assert!(json.get("code").is_none());
        Ok(())
    }

    #[test]
    fn test_error_body_special_chars() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "Invalid \"field\" with <html> & 'quotes'".to_string(),
            code: Some("BAD_REQUEST".to_string()),
        };
        let json_str = serde_json::to_string(&body)?;
        let parsed: serde_json::Value = serde_json::from_str(&json_str)?;
        assert_eq!(parsed["error"], "Invalid \"field\" with <html> & 'quotes'");
        Ok(())
    }

    #[test]
    fn test_error_body_empty_error() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let body = ErrorBody {
            error: "".to_string(),
            code: Some("INTERNAL_ERROR".to_string()),
        };
        let json = serde_json::to_value(&body)?;
        assert_eq!(json["error"], "");
        assert_eq!(json["code"], "INTERNAL_ERROR");
        Ok(())
    }

    /* ========================================================================== */
    /*                    TO_RESPONSE MAPPING TESTS                              */
    /* ========================================================================== */
    /*
       to_response() requires the Worker wasm runtime for Response::from_json(),
       so we cannot call it directly in native tests. Instead we test the
       mapping logic by verifying the (status, code, message) tuples that
       to_response() would produce for each variant.
    */

    /// Helper that extracts the (status, error_code, message) tuple from an ApiError,
    /// matching the same logic as to_response().
    /// Helper that extracts the (status, error_code, message) tuple from an ApiError,
    /// matching the same sanitisation logic as to_response().
    fn error_mapping(err: &ApiError) -> (u16, &'static str, String) {
        match err {
            ApiError::BadRequest(msg) => {
                // Must match the allowlist in to_response().
                let safe = match msg.as_str() {
                    "Missing required field"
                    | "Invalid request format"
                    | "Invalid identifier format"
                    | "Invalid encoding"
                    | "Payload too large"
                    | "Proof verification failed" => msg.clone(),
                    _ => "Invalid request".to_string(),
                };
                (400, "BAD_REQUEST", safe)
            }
            ApiError::NotFound(_) => (404, "NOT_FOUND", "Not found".to_string()),
            ApiError::Unauthorized(_) => {
                (401, "UNAUTHORIZED", "Authentication required".to_string())
            }
            ApiError::Forbidden(_) => (403, "FORBIDDEN", "Access denied".to_string()),
            ApiError::SessionExpired => (
                401,
                "SESSION_EXPIRED",
                "Authentication required".to_string(),
            ),
            ApiError::InvalidSignature(_) => (
                401,
                "INVALID_SIGNATURE",
                "Authentication required".to_string(),
            ),
            ApiError::InvalidProof(_) => (
                400,
                "INVALID_PROOF",
                "Proof verification failed".to_string(),
            ),
            ApiError::RateLimitExceeded => (
                429,
                "RATE_LIMIT_EXCEEDED",
                "Rate limit exceeded".to_string(),
            ),
            ApiError::Conflict(_) => (409, "CONFLICT", "Resource conflict".to_string()),
            ApiError::PayloadTooLarge(_) => {
                (413, "PAYLOAD_TOO_LARGE", "Payload too large".to_string())
            }
            ApiError::UnsupportedMediaType(_) => (
                415,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json".to_string(),
            ),
            ApiError::LengthRequired(_) => (411, "LENGTH_REQUIRED", "Length required".to_string()),
            ApiError::InvalidStateTransition(_) => (
                409,
                "INVALID_STATE_TRANSITION",
                "Invalid state transition".to_string(),
            ),
            ApiError::CryptoError(_) => {
                (500, "INTERNAL_ERROR", "Internal server error".to_string())
            }
            ApiError::StorageError(_) => {
                (500, "INTERNAL_ERROR", "Internal server error".to_string())
            }
            ApiError::Worker(_) => (500, "INTERNAL_ERROR", "Internal server error".to_string()),
            ApiError::Json(_) => (400, "BAD_REQUEST", "Invalid request format".to_string()),
            ApiError::Uuid(_) => (400, "BAD_REQUEST", "Invalid identifier format".to_string()),
            ApiError::Base64(_) => (400, "BAD_REQUEST", "Invalid encoding".to_string()),
            ApiError::Internal(_) => (500, "INTERNAL_ERROR", "Internal server error".to_string()),
            ApiError::ServiceUnavailable(_) => (
                503,
                "SERVICE_UNAVAILABLE",
                "Service temporarily unavailable".to_string(),
            ),
        }
    }

    #[test]
    fn test_mapping_bad_request() {
        // Non-allowlisted message gets sanitised to "Invalid request"
        let err = ApiError::BadRequest("missing field".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 400);
        assert_eq!(code, "BAD_REQUEST");
        assert_eq!(msg, "Invalid request");
    }

    #[test]
    fn test_mapping_bad_request_allowlisted() {
        // Allowlisted message passes through unchanged
        let err = ApiError::BadRequest("Missing required field".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 400);
        assert_eq!(code, "BAD_REQUEST");
        assert_eq!(msg, "Missing required field");
    }

    #[test]
    fn test_mapping_not_found() {
        let err = ApiError::NotFound("session-123".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 404);
        assert_eq!(code, "NOT_FOUND");
        assert_eq!(msg, "Not found");
    }

    #[test]
    fn test_mapping_unauthorized() {
        let err = ApiError::Unauthorized("invalid token".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 401);
        assert_eq!(code, "UNAUTHORIZED");
        assert_eq!(msg, "Authentication required");
    }

    #[test]
    fn test_mapping_forbidden() {
        let err = ApiError::Forbidden("access denied".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 403);
        assert_eq!(code, "FORBIDDEN");
        assert_eq!(msg, "Access denied");
    }

    #[test]
    fn test_mapping_session_expired() {
        let err = ApiError::SessionExpired;
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 401);
        assert_eq!(code, "SESSION_EXPIRED");
        assert_eq!(msg, "Authentication required");
    }

    #[test]
    fn test_mapping_invalid_signature() {
        let err = ApiError::InvalidSignature("HMAC mismatch".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 401);
        assert_eq!(code, "INVALID_SIGNATURE");
        assert_eq!(msg, "Authentication required");
    }

    #[test]
    fn test_mapping_invalid_proof() {
        let err = ApiError::InvalidProof("commitment mismatch".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 400);
        assert_eq!(code, "INVALID_PROOF");
        assert_eq!(msg, "Proof verification failed");
    }

    #[test]
    fn test_mapping_rate_limit() {
        let err = ApiError::RateLimitExceeded;
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 429);
        assert_eq!(code, "RATE_LIMIT_EXCEEDED");
        assert_eq!(msg, "Rate limit exceeded");
    }

    #[test]
    fn test_mapping_invalid_state_transition() {
        let err = ApiError::InvalidStateTransition("already consumed".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 409);
        assert_eq!(code, "INVALID_STATE_TRANSITION");
        // Sanitised: raw message not leaked
        assert_eq!(msg, "Invalid state transition");
    }

    #[test]
    fn test_mapping_crypto_error_sanitised() {
        let err = ApiError::CryptoError("secret key derivation details".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 500);
        assert_eq!(code, "INTERNAL_ERROR");
        assert_eq!(msg, "Internal server error");
    }

    #[test]
    fn test_mapping_storage_error_sanitised() {
        let err = ApiError::StorageError("KV connection string: abc123".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 500);
        assert_eq!(code, "INTERNAL_ERROR");
        assert_eq!(msg, "Internal server error");
    }

    #[test]
    fn test_mapping_internal_error_sanitised() {
        let err = ApiError::Internal("stack trace at line 42".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 500);
        assert_eq!(code, "INTERNAL_ERROR");
        assert_eq!(msg, "Internal server error");
    }

    #[test]
    fn test_mapping_json_error_sanitised() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad")
            .err()
            .ok_or("expected error")?;
        let err = ApiError::Json(json_err);
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 400);
        assert_eq!(code, "BAD_REQUEST");
        assert_eq!(msg, "Invalid request format");
        Ok(())
    }

    #[test]
    fn test_mapping_uuid_error_sanitised() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let uuid_err = uuid::Uuid::parse_str("not-uuid")
            .err()
            .ok_or("expected error")?;
        let err = ApiError::Uuid(uuid_err);
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 400);
        assert_eq!(code, "BAD_REQUEST");
        assert_eq!(msg, "Invalid identifier format");
        Ok(())
    }

    #[test]
    fn test_mapping_base64_error_sanitised() -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        use base64::Engine;
        let b64_err = base64::engine::general_purpose::STANDARD
            .decode("!!!")
            .err()
            .ok_or("expected error")?;
        let err = ApiError::Base64(b64_err);
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 400);
        assert_eq!(code, "BAD_REQUEST");
        assert_eq!(msg, "Invalid encoding");
        Ok(())
    }

    /* ========================================================================== */
    /*                    REMAINING From<crypto_commons::Error> BRANCHES         */
    /* ========================================================================== */

    #[test]
    fn test_from_crypto_invalid_input() {
        let crypto_err = provii_crypto_commons::Error::InvalidInput;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::BadRequest(_)));
        assert_eq!(api_err.to_string(), "Invalid request: Invalid input");
    }

    #[test]
    fn test_from_crypto_invalid_proof() {
        let crypto_err = provii_crypto_commons::Error::InvalidProof;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::InvalidProof(_)));
        assert_eq!(api_err.to_string(), "Invalid proof: Invalid proof");
    }

    #[test]
    fn test_from_crypto_not_found() {
        let crypto_err = provii_crypto_commons::Error::NotFound;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::NotFound(_)));
        assert_eq!(api_err.to_string(), "Not found: Resource not found");
    }

    #[test]
    fn test_from_crypto_rate_limit_exceeded() {
        let crypto_err = provii_crypto_commons::Error::RateLimitExceeded;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::RateLimitExceeded));
        assert_eq!(api_err.to_string(), "Rate limit exceeded");
    }

    #[test]
    fn test_from_crypto_invalid_origin_hash() {
        let crypto_err = provii_crypto_commons::Error::InvalidOriginHash;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::BadRequest(_)));
        assert_eq!(api_err.to_string(), "Invalid request: Invalid request");
    }

    #[test]
    fn test_from_crypto_missing_timestamp() {
        let crypto_err = provii_crypto_commons::Error::MissingTimestamp;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_from_crypto_future_timestamp() {
        let crypto_err = provii_crypto_commons::Error::FutureTimestamp;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_from_crypto_field_too_long() {
        let crypto_err = provii_crypto_commons::Error::FieldTooLong;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::BadRequest(_)));
    }

    #[test]
    fn test_from_crypto_credential_banned() {
        let crypto_err = provii_crypto_commons::Error::CredentialBanned;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::Forbidden(_)));
        assert_eq!(api_err.to_string(), "Forbidden: Credential banned");
    }

    #[test]
    fn test_from_crypto_nullifier_store_failure() {
        let crypto_err = provii_crypto_commons::Error::NullifierStoreFailure;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
    }

    #[test]
    fn test_from_crypto_prover_failed() {
        let crypto_err = provii_crypto_commons::Error::ProverFailed;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
    }

    #[test]
    fn test_from_crypto_verifier_not_initialized() {
        let crypto_err = provii_crypto_commons::Error::VerifierNotInitialized;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
    }

    #[test]
    fn test_from_crypto_already_initialized() {
        let crypto_err = provii_crypto_commons::Error::AlreadyInitialized;
        let api_err: ApiError = crypto_err.into();
        assert!(matches!(api_err, ApiError::Internal(_)));
    }

    /* ========================================================================== */
    /*                    From<LogicError> BRANCHES                              */
    /* ========================================================================== */

    #[test]
    fn test_from_logic_error_bad_request() {
        let logic_err = issuer_logic::error::LogicError::BadRequest("field missing".to_string());
        let api_err: ApiError = logic_err.into();
        assert!(matches!(api_err, ApiError::BadRequest(_)));
        assert_eq!(api_err.to_string(), "Invalid request: field missing");
    }

    #[test]
    fn test_from_logic_error_crypto_error() {
        let logic_err = issuer_logic::error::LogicError::CryptoError("AES failed".to_string());
        let api_err: ApiError = logic_err.into();
        assert!(matches!(api_err, ApiError::CryptoError(_)));
        assert_eq!(api_err.to_string(), "Crypto error: AES failed");
    }

    /* ========================================================================== */
    /*                    REMAINING WorkerError CONVERSION BRANCHES              */
    /* ========================================================================== */

    #[test]
    fn test_into_worker_error_not_found() {
        let api_err = ApiError::NotFound("session-123".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Not found"));
    }

    #[test]
    fn test_into_worker_error_forbidden() {
        let api_err = ApiError::Forbidden("no access".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Forbidden"));
    }

    #[test]
    fn test_into_worker_error_session_expired() {
        let api_err = ApiError::SessionExpired;
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Session expired"));
    }

    #[test]
    fn test_into_worker_error_rate_limit() {
        let api_err = ApiError::RateLimitExceeded;
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Rate limit exceeded"));
    }

    #[test]
    fn test_into_worker_error_conflict() {
        let api_err = ApiError::Conflict("duplicate key".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Conflict"));
    }

    #[test]
    fn test_into_worker_error_payload_too_large() {
        let api_err = ApiError::PayloadTooLarge("over 1MB".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Payload too large"));
    }

    #[test]
    fn test_into_worker_error_unsupported_media_type() {
        let api_err = ApiError::UnsupportedMediaType("text/plain".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Unsupported media type"));
    }

    #[test]
    fn test_into_worker_error_length_required() {
        let api_err = ApiError::LengthRequired("missing Content-Length".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Length required"));
    }

    #[test]
    fn test_into_worker_error_invalid_state_transition() {
        let api_err = ApiError::InvalidStateTransition("already done".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(worker_err.to_string().contains("Invalid state transition"));
    }

    #[test]
    fn test_into_worker_error_crypto_sanitised() {
        let api_err = ApiError::CryptoError("secret key details".to_string());
        let worker_err: WorkerError = api_err.into();
        // SECURITY: Must NOT contain internal crypto details
        assert!(!worker_err.to_string().contains("secret key details"));
        assert!(worker_err.to_string().contains("Internal server error"));
    }

    #[test]
    fn test_into_worker_error_storage_sanitised() {
        let api_err = ApiError::StorageError("KV connection string".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(!worker_err.to_string().contains("KV connection string"));
        assert!(worker_err.to_string().contains("Internal server error"));
    }

    #[test]
    fn test_into_worker_error_internal_sanitised() {
        let api_err = ApiError::Internal("stack trace".to_string());
        let worker_err: WorkerError = api_err.into();
        assert!(!worker_err.to_string().contains("stack trace"));
        assert!(worker_err.to_string().contains("Internal server error"));
    }

    #[test]
    fn test_into_worker_error_service_unavailable() {
        let api_err = ApiError::ServiceUnavailable("maintenance".to_string());
        let worker_err: WorkerError = api_err.into();
        // ServiceUnavailable falls through to the catch-all
        assert!(worker_err.to_string().contains("Internal server error"));
    }

    /* ========================================================================== */
    /*                    REMAINING DISPLAY TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_conflict_display() {
        let err = ApiError::Conflict("duplicate resource".to_string());
        assert_eq!(err.to_string(), "Conflict: duplicate resource");
    }

    #[test]
    fn test_payload_too_large_display() {
        let err = ApiError::PayloadTooLarge("exceeds 1 MB".to_string());
        assert_eq!(err.to_string(), "Payload too large: exceeds 1 MB");
    }

    #[test]
    fn test_unsupported_media_type_display() {
        let err = ApiError::UnsupportedMediaType("text/html".to_string());
        assert_eq!(err.to_string(), "Unsupported media type: text/html");
    }

    #[test]
    fn test_length_required_display() {
        let err = ApiError::LengthRequired("missing header".to_string());
        assert_eq!(err.to_string(), "Length required: missing header");
    }

    #[test]
    fn test_service_unavailable_display() {
        let err = ApiError::ServiceUnavailable("overloaded".to_string());
        assert_eq!(err.to_string(), "Service unavailable: overloaded");
    }

    #[test]
    fn test_worker_error_display() {
        let worker_err = WorkerError::from("test error".to_string());
        let err = ApiError::Worker(worker_err);
        assert!(err.to_string().starts_with("Worker error:"));
    }

    /* ========================================================================== */
    /*                    REMAINING MAPPING TESTS                                */
    /* ========================================================================== */

    #[test]
    fn test_mapping_conflict() {
        let err = ApiError::Conflict("duplicate".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 409);
        assert_eq!(code, "CONFLICT");
        assert_eq!(msg, "Resource conflict");
    }

    #[test]
    fn test_mapping_payload_too_large() {
        let err = ApiError::PayloadTooLarge("too big".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 413);
        assert_eq!(code, "PAYLOAD_TOO_LARGE");
        assert_eq!(msg, "Payload too large");
    }

    #[test]
    fn test_mapping_unsupported_media_type() {
        let err = ApiError::UnsupportedMediaType("text/plain".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 415);
        assert_eq!(code, "UNSUPPORTED_MEDIA_TYPE");
        assert_eq!(msg, "Content-Type must be application/json");
    }

    #[test]
    fn test_mapping_length_required() {
        let err = ApiError::LengthRequired("missing".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 411);
        assert_eq!(code, "LENGTH_REQUIRED");
        assert_eq!(msg, "Length required");
    }

    #[test]
    fn test_mapping_service_unavailable() {
        let err = ApiError::ServiceUnavailable("overloaded".to_string());
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 503);
        assert_eq!(code, "SERVICE_UNAVAILABLE");
        assert_eq!(msg, "Service temporarily unavailable");
    }

    #[test]
    fn test_mapping_worker_error_sanitised() {
        let worker_err = WorkerError::from("internal worker details".to_string());
        let err = ApiError::Worker(worker_err);
        let (status, code, msg) = error_mapping(&err);
        assert_eq!(status, 500);
        assert_eq!(code, "INTERNAL_ERROR");
        assert_eq!(msg, "Internal server error");
    }

    /* ========================================================================== */
    /*                    BAD_REQUEST ALLOWLIST EXHAUSTIVE TESTS                 */
    /* ========================================================================== */

    #[test]
    fn test_mapping_bad_request_allowlisted_invalid_request_format() {
        let err = ApiError::BadRequest("Invalid request format".to_string());
        let (_, _, msg) = error_mapping(&err);
        assert_eq!(msg, "Invalid request format");
    }

    #[test]
    fn test_mapping_bad_request_allowlisted_invalid_identifier_format() {
        let err = ApiError::BadRequest("Invalid identifier format".to_string());
        let (_, _, msg) = error_mapping(&err);
        assert_eq!(msg, "Invalid identifier format");
    }

    #[test]
    fn test_mapping_bad_request_allowlisted_invalid_encoding() {
        let err = ApiError::BadRequest("Invalid encoding".to_string());
        let (_, _, msg) = error_mapping(&err);
        assert_eq!(msg, "Invalid encoding");
    }

    #[test]
    fn test_mapping_bad_request_allowlisted_payload_too_large() {
        let err = ApiError::BadRequest("Payload too large".to_string());
        let (_, _, msg) = error_mapping(&err);
        assert_eq!(msg, "Payload too large");
    }

    #[test]
    fn test_mapping_bad_request_allowlisted_proof_verification_failed() {
        let err = ApiError::BadRequest("Proof verification failed".to_string());
        let (_, _, msg) = error_mapping(&err);
        assert_eq!(msg, "Proof verification failed");
    }
}
