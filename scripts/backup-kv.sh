#!/usr/bin/env bash
# Backup Cloudflare Workers KV namespaces to R2 or local storage
#
# Usage: ./backup-kv.sh [options]
#
# Options:
#   --full              Full backup of all namespaces
#   --namespace NAME    Backup specific namespace
#   --encrypt           Encrypt backup
#   --output PATH       Output file path
#   --timestamp         Add timestamp to filename
#   --help              Show this help message

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-$WORKER_DIR/backups}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# KV Namespace IDs (read from wrangler.toml or environment)
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

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default options
FULL_BACKUP=false
SPECIFIC_NAMESPACE=""
ENCRYPT=false
OUTPUT=""
ADD_TIMESTAMP=false

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

backup_namespace() {
    local name=$1
    local namespace_id=$2
    local output_dir=$3

    log "Backing up namespace: $name ($namespace_id)"

    # Create namespace directory
    mkdir -p "$output_dir/kv-$name"

    # Get all keys
    local keys
    keys=$(wrangler kv:key list --namespace-id="$namespace_id" --env production 2>/dev/null || echo "[]")

    if [ "$keys" == "[]" ]; then
        warn "Namespace $name is empty or inaccessible"
        return 0
    fi

    # Export each key
    local count=0
    echo "$keys" | jq -r '.[].name' | while read -r key; do
        if [ -n "$key" ]; then
            local value
            value=$(wrangler kv:key get "$key" --namespace-id="$namespace_id" --env production 2>/dev/null || echo "")
            if [ -n "$value" ]; then
                echo "$value" > "$output_dir/kv-$name/${key//\//_}.json"
                ((count++))
            fi
        fi
    done

    log "Backed up $count keys from $name"
}

create_metadata() {
    local output_dir=$1
    local metadata_file="$output_dir/metadata.json"

    cat > "$metadata_file" <<EOF
{
  "backup_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backup_version": "1.0",
  "worker_version": "$(cat $WORKER_DIR/Cargo.toml | grep '^version' | head -1 | sed 's/.*= "\(.*\)"/\1/')",
  "namespaces": [
$(printf '    "%s"' "${!NAMESPACES[@]}" | paste -sd,)
  ]
}
EOF

    log "Created metadata file"
}

create_checksums() {
    local output_dir=$1
    local checksums_file="$output_dir/checksums.txt"

    log "Generating checksums..."
    (cd "$output_dir" && find . -type f -name "*.json" -exec sha256sum {} \; > checksums.txt)
    log "Checksums generated"
}

compress_backup() {
    local source_dir=$1
    local output_file=$2

    log "Compressing backup to $output_file..."
    tar -czf "$output_file" -C "$(dirname "$source_dir")" "$(basename "$source_dir")"
    log "Backup compressed: $(du -h "$output_file" | cut -f1)"
}

encrypt_backup() {
    local input_file=$1
    local output_file="${input_file}.enc"

    log "Encrypting backup..."
    if [ -f "$HOME/.backup-passphrase" ]; then
        openssl enc -aes-256-cbc -salt -pbkdf2 -in "$input_file" -out "$output_file" -pass file:"$HOME/.backup-passphrase"
    else
        openssl enc -aes-256-cbc -salt -pbkdf2 -in "$input_file" -out "$output_file"
    fi

    log "Backup encrypted: $output_file"
    rm "$input_file"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            FULL_BACKUP=true
            shift
            ;;
        --namespace)
            SPECIFIC_NAMESPACE="$2"
            shift 2
            ;;
        --encrypt)
            ENCRYPT=true
            shift
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --timestamp)
            ADD_TIMESTAMP=true
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
    log "Starting KV backup process..."

    check_dependencies

    # Create backup directory
    mkdir -p "$BACKUP_DIR"

    # Determine output file
    if [ -z "$OUTPUT" ]; then
        if [ "$ADD_TIMESTAMP" == true ]; then
            OUTPUT="$BACKUP_DIR/backup-$TIMESTAMP.tar.gz"
        else
            OUTPUT="$BACKUP_DIR/backup-latest.tar.gz"
        fi
    fi

    # Create temporary directory
    local temp_dir
    temp_dir=$(mktemp -d)
    trap "rm -rf '$temp_dir'" EXIT

    # Create metadata
    create_metadata "$temp_dir"

    # Perform backup
    if [ -n "$SPECIFIC_NAMESPACE" ]; then
        if [ -n "${NAMESPACES[$SPECIFIC_NAMESPACE]}" ]; then
            backup_namespace "$SPECIFIC_NAMESPACE" "${NAMESPACES[$SPECIFIC_NAMESPACE]}" "$temp_dir"
        else
            error "Unknown namespace: $SPECIFIC_NAMESPACE"
            exit 1
        fi
    else
        for name in "${!NAMESPACES[@]}"; do
            if [ -n "${NAMESPACES[$name]}" ]; then
                backup_namespace "$name" "${NAMESPACES[$name]}" "$temp_dir"
            else
                warn "Namespace ID not set for $name, skipping"
            fi
        done
    fi

    # Create checksums
    create_checksums "$temp_dir"

    # Compress
    compress_backup "$temp_dir" "$OUTPUT"

    # Encrypt if requested
    if [ "$ENCRYPT" == true ]; then
        encrypt_backup "$OUTPUT"
        OUTPUT="${OUTPUT}.enc"
    fi

    log "Backup completed successfully: $OUTPUT"
    log "Backup size: $(du -h "$OUTPUT" | cut -f1)"
}

main "$@"
