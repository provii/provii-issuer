// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust

//! SSRF Protection for Service URLs
//!
//! This module provides Server-Side Request Forgery (SSRF) protection for
//! internal service URLs to prevent attackers from using the issuer service
//! to make requests to internal or cloud metadata endpoints.
//!
//! OWASP ASVS 5.0.0 V13.2.6 [L2]: Applications should validate webhook URLs to prevent SSRF attacks.
//!
//! ## DNS Rebinding (Accepted Risk)
//!
//! DNS rebinding attacks (where a hostname resolves to a safe IP initially, then
//! resolves to an internal IP on subsequent requests) cannot be fully mitigated in
//! Cloudflare Workers. The Workers runtime does not expose raw DNS resolution APIs,
//! and the fetch API resolves DNS internally. This is an accepted risk because:
//!
//! 1. CF Workers run on Cloudflare's edge, not inside customer VPCs, so there are
//!    no internal services reachable via private IPs from the Workers runtime.
//! 2. The Workers fetch API enforces its own restrictions on certain internal ranges.
//! 3. URL validation at registration time blocks the most common SSRF vectors.

use crate::error::{ApiError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Checks if a hostname represents localhost or loopback
fn is_localhost(host: &str) -> bool {
    // SSRF-033: Case-insensitive comparison for hostnames.
    let host_lower = host.to_lowercase();

    // Common localhost names
    if host_lower == "localhost" || host_lower == "localhost.localdomain" {
        return true;
    }

    // IPv4 loopback
    if host_lower.starts_with("127.") {
        return true;
    }

    // IPv6 loopback
    if host_lower == "::1" || host_lower == "[::1]" {
        return true;
    }

    // Check if it's an IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback();
    }

    false
}

/// Checks if a hostname is a cloud metadata endpoint
fn is_cloud_metadata(host: &str) -> bool {
    // SSRF-033: Case-insensitive comparison for hostnames.
    let host_lower = host.to_lowercase();

    // AWS/GCP/Azure metadata endpoint
    if host_lower == "169.254.169.254" {
        return true;
    }

    // SSRF-031: Tailscale/cloud metadata endpoint
    if host_lower == "100.100.100.200" {
        return true;
    }

    // GCP metadata endpoints
    if host_lower == "metadata.google.internal"
        || host_lower == "metadata"
        || host_lower.ends_with(".metadata.google.internal")
    {
        return true;
    }

    // Azure WireServer / IMDS alternative endpoint
    if host_lower == "168.63.129.16" {
        return true;
    }

    // AWS IMDSv2 (IPv6)
    if host_lower == "fd00:ec2::254" || host_lower == "[fd00:ec2::254]" {
        return true;
    }

    false
}

/// Checks if an IP address is private or restricted
fn is_private_or_restricted_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_or_restricted_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_or_restricted_ipv6(ipv6),
    }
}

/// Checks if an IPv4 address is private or restricted
fn is_private_or_restricted_ipv4(ip: &Ipv4Addr) -> bool {
    // Loopback (127.0.0.0/8)
    if ip.is_loopback() {
        return true;
    }

    // Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    if ip.is_private() {
        return true;
    }

    // Link-local (169.254.0.0/16) - includes cloud metadata
    if ip.is_link_local() {
        return true;
    }

    // Broadcast
    if ip.is_broadcast() {
        return true;
    }

    // Documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if ip.is_documentation() {
        return true;
    }

    let octets = ip.octets();

    // SSRF-029: "This network" (0.0.0.0/8), not just the unspecified address.
    // Any address with first octet == 0 is reserved per RFC 791.
    if octets[0] == 0 {
        return true;
    }

    // Multicast (224.0.0.0/4)
    if octets[0] >= 224 && octets[0] <= 239 {
        return true;
    }

    // Reserved (240.0.0.0/4)
    if octets[0] >= 240 {
        return true;
    }

    // SSRF-031: Tailscale/cloud metadata endpoint (100.100.100.200) sits inside
    // the CGNAT range but warrants a specific cloud metadata error message.
    // Checked here so the CGNAT catch-all below does not mask it.
    if *ip == Ipv4Addr::new(100, 100, 100, 200) {
        return true;
    }

    // Carrier-grade NAT (100.64.0.0/10)
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000 {
        return true;
    }

    false
}

/// Checks if an IPv6 address is private or restricted
fn is_private_or_restricted_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback (::1)
    if ip.is_loopback() {
        return true;
    }

    // Unspecified (::)
    if ip.is_unspecified() {
        return true;
    }

    // Multicast (ff00::/8)
    if ip.is_multicast() {
        return true;
    }

    let segments = ip.segments();

    // Link-local (fe80::/10)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // Unique local addresses (fc00::/7)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // Documentation (2001:db8::/32)
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    // AWS IMDSv2 (fd00:ec2::254)
    if segments[0] == 0xfd00
        && segments[1] == 0x0ec2
        && segments[2..7] == [0, 0, 0, 0, 0]
        && segments[7] == 0x0254
    {
        return true;
    }

    // IPv4-mapped IPv6 addresses (::ffff:0:0/96)
    // These can bypass IPv4 checks, so validate the embedded IPv4 address
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_or_restricted_ipv4(&ipv4);
    }

    // IPv4-compatible IPv6 addresses (deprecated ::x.x.x.x form, RFC 4291 S2.5.5.1)
    // to_ipv4() catches both mapped and compatible forms
    #[allow(deprecated)]
    if let Some(ipv4) = ip.to_ipv4() {
        return is_private_or_restricted_ipv4(&ipv4);
    }

    // IPv6 site-local addresses (fec0::/10) - deprecated but check anyway
    if (segments[0] & 0xffc0) == 0xfec0 {
        return true;
    }

    false
}

/// Validates an internal service URL (e.g. `CREDIT_MGMT_URL`) against SSRF attacks.
///
/// SSRF-085: Service URLs configured via environment variables must still be validated
/// before making outbound HTTP requests. This is a defence-in-depth measure: even
/// though the URL comes from a trusted configuration source, a compromised or
/// misconfigured env var could point to an internal endpoint.
///
/// This function:
/// - Allows both HTTP and HTTPS (some internal services may use HTTP over service bindings)
/// - Does not enforce an allowlist (the URL is operator-configured, not user-supplied)
/// - Still blocks private IPs, localhost, cloud metadata, and .local domains
pub fn validate_service_url(url: &str) -> Result<Url> {
    let parsed = Url::parse(url)
        .map_err(|_| ApiError::BadRequest("Invalid service URL format".to_string()))?;

    // Only allow http/https schemes
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err(ApiError::BadRequest(
            "Service URL must use HTTP or HTTPS protocol".to_string(),
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("Service URL must have a valid host".to_string()))?;

    if is_localhost(host) {
        return Err(ApiError::BadRequest(
            "Service URL cannot point to localhost or loopback addresses".to_string(),
        ));
    }

    if is_cloud_metadata(host) {
        return Err(ApiError::BadRequest(
            "Service URL cannot point to cloud metadata endpoints".to_string(),
        ));
    }

    let host_clean = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_clean.parse::<IpAddr>() {
        if is_private_or_restricted_ip(&ip) {
            return Err(ApiError::BadRequest(
                "Service URL cannot point to private or restricted IP addresses".to_string(),
            ));
        }
    }

    let host_lower = host.to_lowercase();
    if host_lower.ends_with(".local") || host_lower == "local" {
        return Err(ApiError::BadRequest(
            "Service URL cannot use .local domains (mDNS)".to_string(),
        ));
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("127.0.0.255"));
        assert!(is_localhost("::1"));
        assert!(!is_localhost("example.com"));
        assert!(!is_localhost("192.168.1.1"));
    }

    #[test]
    fn test_is_cloud_metadata() {
        assert!(is_cloud_metadata("169.254.169.254"));
        assert!(is_cloud_metadata("metadata.google.internal"));
        assert!(is_cloud_metadata("metadata"));
        assert!(is_cloud_metadata("fd00:ec2::254"));
        assert!(!is_cloud_metadata("example.com"));
    }

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(
            192, 168, 1, 1
        )));
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(
            169, 254, 1, 1
        )));
        assert!(!is_private_or_restricted_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    // SSRF-085: Service URL validation tests.
    #[test]
    fn test_validate_service_url_valid_https() {
        let result = validate_service_url("https://credit-management.provii.workers.dev");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_service_url_valid_http() {
        let result = validate_service_url("http://credit-management.provii.workers.dev");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_service_url_reject_localhost() {
        let result = validate_service_url("https://localhost:8080/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_service_url_reject_private_ip() {
        let result = validate_service_url("https://10.0.0.1/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_service_url_reject_metadata() {
        let result = validate_service_url("https://169.254.169.254/latest/meta-data");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_service_url_reject_ftp() {
        let result = validate_service_url("ftp://example.com/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_private_ipv6_loopback() {
        assert!(is_private_or_restricted_ipv6(&"::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_unspecified() {
        assert!(is_private_or_restricted_ipv6(&"::".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_link_local() {
        assert!(is_private_or_restricted_ipv6(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_unique_local() {
        assert!(is_private_or_restricted_ipv6(&"fd00::1".parse().unwrap()));
        assert!(is_private_or_restricted_ipv6(&"fc00::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_documentation() {
        assert!(is_private_or_restricted_ipv6(
            &"2001:db8::1".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ipv6_aws_imds() {
        assert!(is_private_or_restricted_ipv6(
            &"fd00:ec2::254".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ipv6_mapped_private_v4() {
        // ::ffff:10.0.0.1 should be detected as private
        assert!(is_private_or_restricted_ipv6(
            &"::ffff:10.0.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ipv6_public() {
        assert!(!is_private_or_restricted_ipv6(
            &"2606:4700::1".parse().unwrap()
        ));
    }

    #[test]
    fn test_is_private_ipv6_multicast() {
        assert!(is_private_or_restricted_ipv6(&"ff02::1".parse().unwrap()));
    }

    #[test]
    fn test_is_private_ipv6_site_local_deprecated() {
        assert!(is_private_or_restricted_ipv6(&"fec0::1".parse().unwrap()));
    }

    #[test]
    fn test_validate_service_url_reject_dotlocal() {
        let result = validate_service_url("https://my-service.local/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_service_url_reject_no_scheme() {
        let result = validate_service_url("://no-scheme/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_service_url_reject_invalid_format() {
        let result = validate_service_url("not-a-url");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_service_url_reject_private_ipv6() {
        let result = validate_service_url("https://[::1]/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_cloud_metadata_gcp() {
        assert!(is_cloud_metadata("metadata.google.internal"));
    }

    #[test]
    fn test_is_cloud_metadata_bare() {
        assert!(is_cloud_metadata("metadata"));
    }

    #[test]
    fn test_is_localhost_ipv4_full_range() {
        assert!(is_localhost("127.0.0.0"));
        assert!(is_localhost("127.255.255.255"));
    }

    #[test]
    fn test_is_private_ipv4_link_local() {
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(
            169, 254, 0, 1
        )));
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(
            169, 254, 255, 254
        )));
    }

    #[test]
    fn test_is_private_ipv4_class_b_private() {
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(
            172, 31, 255, 255
        )));
        assert!(!is_private_or_restricted_ipv4(&Ipv4Addr::new(
            172, 32, 0, 1
        )));
    }

    #[test]
    fn test_is_private_ipv4_broadcast() {
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(
            255, 255, 255, 255
        )));
    }

    #[test]
    fn test_is_private_ipv4_unspecified() {
        assert!(is_private_or_restricted_ipv4(&Ipv4Addr::new(0, 0, 0, 0)));
    }
}
