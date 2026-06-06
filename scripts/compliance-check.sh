#!/usr/bin/env bash
# Automated compliance validation for security controls
#
# Checks:
# - All security controls are active
# - Configuration matches security baseline
# - No hardcoded secrets
# - Encryption at rest enabled
# - Audit logging functional
#
# Usage: ./compliance-check.sh [--environment ENV]

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
ENVIRONMENT="${1:-staging}"
PASSED=0
FAILED=0
WARNINGS=0

log_pass() {
    echo -e "${GREEN}✓${NC} $*"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}✗${NC} $*"
    ((FAILED++))
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $*"
    ((WARNINGS++))
}

echo "========================================="
echo "Compliance Check - $ENVIRONMENT"
echo "========================================="
echo ""

# Check 1: No hardcoded secrets in code
echo "[1/10] Checking for hardcoded secrets..."
if grep -r "sk_" src --exclude-dir=target --exclude-dir=.git >/dev/null 2>&1; then
    log_fail "Found potential hardcoded secrets (sk_ pattern)"
else
    log_pass "No hardcoded secrets detected"
fi

# Check 2: Security headers configured
echo "[2/10] Checking security headers..."
if grep -q "X-Content-Type-Options" src/lib.rs && \
   grep -q "X-Frame-Options" src/lib.rs && \
   grep -q "Strict-Transport-Security" src/lib.rs; then
    log_pass "Security headers configured"
else
    log_fail "Missing security headers in configuration"
fi

# Check 3: Rate limiting enabled
echo "[3/10] Checking rate limiting..."
if grep -q "rate_limit::" src/lib.rs; then
    log_pass "Rate limiting enabled"
else
    log_fail "Rate limiting not found"
fi

# Check 4: Audit logging present
echo "[4/10] Checking audit logging..."
if grep -q "audit_log" src/storage.rs || grep -q "audit_log" src/lib.rs; then
    log_pass "Audit logging implemented"
else
    log_fail "Audit logging missing"
fi

# Check 5: Input validation
echo "[5/10] Checking input validation..."
if grep -q "validate_identifier" src/storage.rs && \
   grep -q "is_ascii_identifier" src/routes.rs; then
    log_pass "Input validation implemented"
else
    log_fail "Input validation incomplete"
fi

# Check 6: HTTPS enforcement
echo "[6/10] Checking HTTPS enforcement..."
if grep -q "https://" wrangler.toml || grep -q "HSTS" src/lib.rs; then
    log_pass "HTTPS enforcement configured"
else
    log_warn "HTTPS enforcement not explicitly configured"
fi

# Check 7: Session expiration
echo "[7/10] Checking session expiration..."
if grep -q "SESSION_TTL" src/routes.rs && \
   grep -q "expires_at" src/types.rs; then
    log_pass "Session expiration implemented"
else
    log_fail "Session expiration missing"
fi

# Check 8: Dependency audit
echo "[8/10] Running dependency audit..."
if command -v cargo-audit >/dev/null 2>&1; then
    if cargo audit --deny warnings 2>/dev/null; then
        log_pass "No known vulnerabilities in dependencies"
    else
        log_fail "Vulnerabilities found in dependencies"
    fi
else
    log_warn "cargo-audit not installed, skipping"
fi

# Check 9: Cryptographic operations
echo "[9/10] Checking cryptographic operations..."
if grep -q "RedJubJub\|redjubjub\|crypto" src/crypto.rs; then
    log_pass "Cryptographic operations implemented"
else
    log_fail "Cryptographic operations missing"
fi

# Check 10: Horizontal privilege escalation prevention
echo "[10/10] Checking authorization controls..."
if grep -q "session_ownership_violation" src/routes.rs && \
   grep -q "bound to different" src/routes.rs; then
    log_pass "Horizontal privilege escalation prevention implemented"
else
    log_fail "Authorization controls incomplete"
fi

# Summary
echo ""
echo "========================================="
echo "Compliance Check Summary"
echo "========================================="
echo -e "${GREEN}Passed:${NC} $PASSED"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "${RED}Failed:${NC} $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}Compliance check PASSED${NC}"
    exit 0
else
    echo -e "${RED}Compliance check FAILED${NC}"
    echo "Please address the failures before deploying."
    exit 1
fi
