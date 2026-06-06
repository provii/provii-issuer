// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! Error types for the issuer-logic crate.

use thiserror::Error;

/// Errors produced by pure business logic operations.
///
/// These map 1:1 to the Worker-facing `ApiError` variants in the root crate.
/// The root crate implements `From<LogicError>` for `ApiError`.
#[derive(Debug, Error)]
pub enum LogicError {
    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, LogicError>;
