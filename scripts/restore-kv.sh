#!/usr/bin/env bash
# Restore Cloudflare Workers KV namespaces from backup
#
# Usage: ./restore-kv.sh [options]
#
# Options:
#   --source PATH       Backup file to restore from (required)
#   --namespace NAME    Restore specific namespace
#   --environment ENV   Target environment (staging/production)
#   --dry-run           Simulate restoration without making changes
#   --force             Force overwrite existing data
#   --help              Show this help message

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
SOURCE_FILE=""
SPECIFIC_NAMESPACE=""
ENVIRONMENT="staging"
DRY_RUN=false
FORCE=false

# KV Namespace IDs
declare -A NAMESPACES=(
    ["CONFIG"]="${KV_CONFIG:-}"
    ["KEYS"]="${KV_KEYS:-}"
    ["SESSIONS"]="${KV_SESSIONS:-}"
    ["CHALLENGES"]="${KV_CHALLENGES:-}"
    ["PICKUP"]="${KV_PICKUP:-}"
    ["OFFICER_REGISTRY"]="${KV_OFFICER_REGISTRY:-}"
    ["CLIENTS"]="${KV_CLIENTS:-}"
    ["AUDIT_LOG"]="${KV_AUDIT_LOG:-}"
    ["RATE_LIMITS"]="${KV_RATE_LIMITS:-}"
    ["NONCES"]="${KV_NONCES:-}"
)

# Functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

show_help() {
    head -n 20 "$0" | grep "^#" | sed 's/^# //g' | sed 's/^#//g'
    exit 0
}

check_dependencies() {
    local deps=("wrangler" "jq" "tar" "gzip")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "$dep is required but not installed"
            exit 1
        fi
    done
}

decrypt_backup() {
    local input_file=$1
    local output_file="${input_file%.enc}"

    log "Decrypting backup..."
    if [ -f "$HOME/.backup-passphrase" ]; then
        openssl enc -d -aes-256-cbc -pbkdf2 -in "$input_file" -out "$output_file" -pass file:"$HOME/.backup-passphrase"
    else
        openssl enc -d -aes-256-cbc -pbkdf2 -in "$input_file" -out "$output_file"
    fi

    echo "$output_file"
}

extract_backup() {
    local backup_file=$1
    local extract_dir=$2

    log "Extracting backup..."
    mkdir -p "$extract_dir"
    tar -xzf "$backup_file" -C "$extract_dir"
    log "Backup extracted to $extract_dir"
}

verify_backup() {
    local backup_dir=$1

    log "Verifying backup integrity..."

    if [ ! -f "$backup_dir/metadata.json" ]; then
        error "Missing metadata.json in backup"
        return 1
    fi

    if [ ! -f "$backup_dir/checksums.txt" ]; then
        warn "Missing checksums.txt, skipping checksum verification"
        return 0
    fi

    local failed=0
    (cd "$backup_dir" && sha256sum -c checksums.txt --quiet) || failed=1

    if [ $failed -eq 1 ]; then
        error "Checksum verification failed"
        return 1
    fi

    log "Backup integrity verified"
    return 0
}

restore_namespace() {
    local name=$1
    local namespace_id=$2
    local source_dir=$3

    log "Restoring namespace: $name ($namespace_id)"

    local kv_dir="$source_dir/kv-$name"
    if [ ! -d "$kv_dir" ]; then
        warn "No data found for namespace $name, skipping"
        return 0
    fi

    local count=0
    for file in "$kv_dir"/*.json; do
        if [ -f "$file" ]; then
            local key
            key=$(basename "$file" .json | tr '_' '/')
            local value
            value=$(<"$file")

            if [ "$DRY_RUN" == true ]; then
                info "[DRY RUN] Would restore key: $key"
            else
                wrangler kv:key put "$key" \
                    --namespace-id="$namespace_id" \
                    --env "$ENVIRONMENT" \
                    --path "$file" 2>/dev/null || warn "Failed to restore key: $key"
            fi

            ((count++))
        fi
    done

    log "Restored $count keys to $name"
}

confirm_restore() {
    if [ "$FORCE" == true ]; then
        return 0
    fi

    warn "This will overwrite existing data in $ENVIRONMENT environment"
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        error "Restore cancelled by user"
        exit 1
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --source)
            SOURCE_FILE="$2"
            shift 2
            ;;
        --namespace)
            SPECIFIC_NAMESPACE="$2"
            shift 2
            ;;
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --help)
            show_help
            ;;
        *)
            error "Unknown option: $1"
            show_help
            ;;
    esac
done

# Main execution
main() {
    log "Starting KV restore process..."

    check_dependencies

    # Validate required arguments
    if [ -z "$SOURCE_FILE" ]; then
        error "Source file is required (--source)"
        exit 1
    fi

    if [ ! -f "$SOURCE_FILE" ]; then
        error "Source file not found: $SOURCE_FILE"
        exit 1
    fi

    # Validate environment
    if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
        error "Invalid environment: $ENVIRONMENT (must be staging or production)"
        exit 1
    fi

    # Confirm restore (unless dry-run)
    if [ "$DRY_RUN" == false ]; then
        confirm_restore
    fi

    # Create temporary directory
    local temp_dir
    temp_dir=$(mktemp -d)
    trap "rm -rf '$temp_dir'" EXIT

    # Decrypt if necessary
    local backup_file="$SOURCE_FILE"
    if [[ "$SOURCE_FILE" == *.enc ]]; then
        backup_file=$(decrypt_backup "$SOURCE_FILE")
    fi

    # Extract backup
    extract_backup "$backup_file" "$temp_dir"

    # Verify backup
    if ! verify_backup "$temp_dir"; then
        error "Backup verification failed, aborting restore"
        exit 1
    fi

    # Show metadata
    info "Backup metadata:"
    jq '.' "$temp_dir/metadata.json"

    # Perform restore
    if [ -n "$SPECIFIC_NAMESPACE" ]; then
        if [ -n "${NAMESPACES[$SPECIFIC_NAMESPACE]}" ]; then
            restore_namespace "$SPECIFIC_NAMESPACE" "${NAMESPACES[$SPECIFIC_NAMESPACE]}" "$temp_dir"
        else
            error "Unknown namespace: $SPECIFIC_NAMESPACE"
            exit 1
        fi
    else
        for name in "${!NAMESPACES[@]}"; do
            if [ -n "${NAMESPACES[$name]}" ]; then
                restore_namespace "$name" "${NAMESPACES[$name]}" "$temp_dir"
            else
                warn "Namespace ID not set for $name, skipping"
            fi
        done
    fi

    if [ "$DRY_RUN" == true ]; then
        log "Dry run completed - no changes made"
    else
        log "Restore completed successfully"
    fi
}

main "$@"
