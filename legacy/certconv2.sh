#!/usr/bin/env bash
# shellcheck shell=bash
#
# certconv2 - Certificate conversion tool with fzf-powered workflow
#
# A simpler, file-first approach to certificate operations.
# Uses fzf for selection, plain terminal for output.
#
# Requirements: openssl, fzf (for interactive mode)
#

set -euo pipefail

VERSION="2.0.0"
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Environment overrides
CERTCONV_NONINTERACTIVE="${CERTCONV_NONINTERACTIVE:-false}"
CERTCONV_CERTS_DIR="${CERTCONV_CERTS_DIR:-./certs}"

# ═══════════════════════════════════════════════════════════════════════════════
# Output Helpers
# ═══════════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
DIM='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

msg()     { printf '%b\n' "$*"; }
info()    { printf '%b\n' "${BLUE}ℹ${NC}  $*"; }
success() { printf '%b\n' "${GREEN}✓${NC}  $*"; }
warn()    { printf '%b\n' "${YELLOW}⚠${NC}  $*"; }
error()   { printf '%b\n' "${RED}✗${NC}  $*" >&2; }
step()    { printf '%b\n' "${DIM}→${NC}  $*"; }
dim()     { printf '%b\n' "${DIM}$*${NC}"; }

die() {
  error "$1"
  exit "${2:-1}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════════════════════════════════════════

is_true() {
  local val="${1:-}"
  val=$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')
  [[ "$val" =~ ^(true|yes|1)$ ]]
}

is_interactive() {
  # Check if we're allowed to be interactive and have a terminal
  # Use stderr (-t 2) as it's usually connected even when stdout is piped
  # Also accept if /dev/tty is available (fzf uses this directly)
  if is_true "$CERTCONV_NONINTERACTIVE"; then
    return 1
  fi
  [[ -t 2 ]] || [[ -t 0 ]] || [[ -t 1 ]]
}

has_fzf() {
  command -v fzf &>/dev/null
}

lowercase() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'
}

# Resolve path: if bare filename exists in certs dir, use that
resolve_path() {
  local path="$1"
  [[ -z "$path" ]] && return 0

  # Already a path or file exists
  if [[ -f "$path" || "$path" == */* ]]; then
    printf '%s' "$path"
    return 0
  fi

  # Try certs directory
  local certs_dir="${CERTCONV_CERTS_DIR}"
  [[ "$certs_dir" != /* && "$certs_dir" != ./* ]] && certs_dir="${SCRIPT_DIR}/${certs_dir}"
  local candidate="${certs_dir%/}/$path"
  if [[ -f "$candidate" ]]; then
    printf '%s' "$candidate"
    return 0
  fi

  printf '%s' "$path"
}

# ═══════════════════════════════════════════════════════════════════════════════
# fzf Selection
# ═══════════════════════════════════════════════════════════════════════════════

# Pick a file using fzf
pick_file() {
  local prompt="${1:-Select file}"
  local extensions="${2:-pem,crt,cer,key,pfx,p12,der}"
  local start_dir="${3:-${CERTCONV_CERTS_DIR}}"

  if ! is_interactive; then
    error "File selection requires interactive mode"
    return 1
  fi

  if ! has_fzf; then
    error "fzf is required for interactive mode"
    info "Install: brew install fzf"
    return 1
  fi

  [[ "$start_dir" != /* && "$start_dir" != ./* ]] && start_dir="${SCRIPT_DIR}/${start_dir}"
  [[ ! -d "$start_dir" ]] && start_dir="."

  # Build find expression for extensions
  local find_expr=""
  IFS=',' read -ra exts <<< "$extensions"
  for ext in "${exts[@]}"; do
    [[ -n "$find_expr" ]] && find_expr="$find_expr -o "
    find_expr="${find_expr}-iname '*.${ext}'"
  done

  local selected
  selected=$(eval "find '$start_dir' -maxdepth 2 -type f \\( $find_expr \\) 2>/dev/null" | \
    sort | \
    fzf --prompt "$prompt > " \
        --height 15 \
        --reverse \
        --preview 'file {} && head -5 {}' \
        --preview-window=right:40%:wrap) || return 1

  [[ -z "$selected" ]] && return 1
  printf '%s' "$selected"
}

# Pick from a list of options
pick_option() {
  local prompt="$1"
  shift
  local -a options=("$@")

  if ! is_interactive || ! has_fzf; then
    error "Option selection requires interactive mode with fzf"
    return 1
  fi

  printf '%s\n' "${options[@]}" | \
    fzf --prompt "$prompt > " \
        --height $((${#options[@]} + 3)) \
        --reverse \
        --no-preview
}

# Simple y/n confirmation
confirm() {
  local prompt="${1:-Continue?}"

  if ! is_interactive; then
    return 1
  fi

  local answer
  printf '%s [y/N] ' "$prompt"
  read -r answer
  [[ "${answer,,}" =~ ^(y|yes)$ ]]
}

# Read a value with optional default
read_value() {
  local prompt="$1"
  local default="${2:-}"
  local is_password="${3:-false}"

  if ! is_interactive; then
    [[ -n "$default" ]] && printf '%s' "$default" && return 0
    error "Input required but not in interactive mode"
    return 1
  fi

  local value
  if [[ -n "$default" ]]; then
    printf '%s [%s]: ' "$prompt" "$default"
  else
    printf '%s: ' "$prompt"
  fi

  if [[ "$is_password" == "true" ]]; then
    read -rs value
    echo
  else
    read -r value
  fi

  [[ -z "$value" ]] && value="$default"
  printf '%s' "$value"
}

# ═══════════════════════════════════════════════════════════════════════════════
# File Detection
# ═══════════════════════════════════════════════════════════════════════════════

detect_type() {
  local file="$1"
  local ext="${file##*.}"
  ext=$(lowercase "$ext")

  case "$ext" in
    pfx|p12) echo "pfx"; return ;;
    der)     echo "der"; return ;;
    key)     echo "key"; return ;;
    b64|base64) echo "base64"; return ;;
  esac

  # Check content
  local has_cert="" has_key=""
  grep -q "BEGIN CERTIFICATE" "$file" 2>/dev/null && has_cert="yes"
  grep -qE '^-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----$' "$file" 2>/dev/null && has_key="yes"

  if [[ -n "$has_cert" && -n "$has_key" ]]; then
    echo "combined"
  elif [[ -n "$has_cert" ]]; then
    echo "cert"
  elif [[ -n "$has_key" ]]; then
    echo "key"
  else
    echo "unknown"
  fi
}

is_der_encoded() {
  local file="$1"
  local first_byte
  first_byte=$(od -A n -t x1 -N 1 "$file" 2>/dev/null | tr -d ' \n')
  [[ "$first_byte" == "30" ]]
}

# ═══════════════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════════════

require_file() {
  local file="$1"
  local desc="${2:-File}"

  [[ -z "$file" ]] && die "$desc path required"
  [[ ! -f "$file" ]] && die "$desc not found: $file"
  [[ ! -r "$file" ]] && die "$desc not readable: $file"
  return 0
}

validate_pem_cert() {
  local file="$1"

  if ! grep -q "BEGIN CERTIFICATE" "$file" 2>/dev/null; then
    error "Not a PEM certificate: $file"
    dim "  Expected: -----BEGIN CERTIFICATE-----"
    return 1
  fi

  local result
  result=$(openssl x509 -in "$file" -noout 2>&1) || true
  if [[ -n "$result" ]]; then
    error "Invalid X.509 certificate: $file"
    dim "  $result"
    return 1
  fi
  return 0
}

validate_pem_key() {
  local file="$1"

  if ! grep -qE '^-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----$' "$file" 2>/dev/null; then
    error "Not a PEM private key: $file"
    return 1
  fi
  return 0
}

validate_pfx() {
  local file="$1"
  local password="${2:-}"

  local result
  result=$(openssl pkcs12 -in "$file" -noout -passin "pass:${password}" 2>&1) || true
  if [[ "$result" == *"error"* ]] || [[ "$result" == *"Error"* ]] || [[ "$result" == *"invalid"* ]]; then
    error "Invalid PFX or wrong password: $file"
    if [[ "$result" == *"mac verify failure"* ]]; then
      dim "  Incorrect password"
    elif [[ "$result" == *"expecting an asn1 sequence"* ]] || [[ "$result" == *"not a PKCS12"* ]]; then
      dim "  File is not a valid PKCS#12/PFX file"
    else
      dim "  $result"
    fi
    return 1
  fi
  return 0
}

key_matches_cert() {
  local cert="$1"
  local key="$2"

  local cert_mod key_mod
  cert_mod=$(openssl x509 -noout -modulus -in "$cert" 2>/dev/null | openssl md5)
  key_mod=$(openssl rsa -noout -modulus -in "$key" 2>/dev/null | openssl md5)

  [[ "$cert_mod" == "$key_mod" ]]
}

# ═══════════════════════════════════════════════════════════════════════════════
# Clipboard and View Helpers
# ═══════════════════════════════════════════════════════════════════════════════

copy_to_clipboard() {
  if command -v pbcopy &>/dev/null; then
    pbcopy
  elif command -v xclip &>/dev/null; then
    xclip -selection clipboard
  elif command -v xsel &>/dev/null; then
    xsel --clipboard --input
  else
    error "No clipboard command found (pbcopy, xclip, or xsel)"
    return 1
  fi
}

cmd_view() {
  local file="$1"
  require_file "$file" "File"

  if command -v bat &>/dev/null; then
    bat --paging=always --style=plain "$file"
  elif command -v less &>/dev/null; then
    less "$file"
  else
    cat "$file"
  fi
}

cmd_copy() {
  local file="$1"
  require_file "$file" "File"

  local bytes
  bytes=$(wc -c < "$file" | tr -d ' ')
  if cat "$file" | copy_to_clipboard; then
    success "Copied to clipboard ($bytes bytes)"
  else
    return 1
  fi
}

cmd_copy_oneline() {
  local file="$1"
  require_file "$file" "File"

  local content
  content=$(cat "$file" | tr -d '\n\r')
  if printf '%s' "$content" | copy_to_clipboard; then
    success "Copied to clipboard without line breaks (${#content} bytes)"
  else
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Info Commands (Non-invasive)
# ═══════════════════════════════════════════════════════════════════════════════

cmd_show() {
  local file="$1"
  local password="${2:-}"

  require_file "$file" "Certificate"

  local file_type
  file_type=$(detect_type "$file")

  echo
  msg "${BOLD}File:${NC} $file"
  msg "${BOLD}Type:${NC} $file_type"
  echo

  local info=""
  case "$file_type" in
    pfx|p12)
      info=$(openssl pkcs12 -in "$file" -nokeys -passin "pass:$password" 2>/dev/null | \
             openssl x509 -noout -subject -issuer -dates -serial 2>/dev/null)
      ;;
    der)
      info=$(openssl x509 -in "$file" -inform DER -noout -subject -issuer -dates -serial 2>/dev/null)
      ;;
    cert|combined)
      info=$(openssl x509 -in "$file" -noout -subject -issuer -dates -serial 2>/dev/null)
      ;;
    key)
      info="Private key file"
      local key_type
      if grep -q "RSA PRIVATE KEY" "$file" 2>/dev/null; then
        key_type="RSA"
      elif grep -q "EC PRIVATE KEY" "$file" 2>/dev/null; then
        key_type="EC"
      else
        key_type="PKCS#8"
      fi
      info="Private key type: $key_type"
      ;;
    *)
      warn "Unknown file type"
      return 1
      ;;
  esac

  if [[ -n "$info" ]]; then
    while IFS= read -r line; do
      printf '  %s\n' "$line"
    done <<< "$info"
    echo
  fi
}

cmd_show_full() {
  local file="$1"
  local password="${2:-}"

  require_file "$file" "Certificate"

  local file_type
  file_type=$(detect_type "$file")

  local output=""
  case "$file_type" in
    pfx|p12)
      output=$(openssl pkcs12 -in "$file" -nokeys -passin "pass:$password" 2>/dev/null | \
               openssl x509 -text -noout 2>/dev/null)
      ;;
    der)
      output=$(openssl x509 -in "$file" -inform DER -text -noout 2>/dev/null)
      ;;
    cert|combined)
      output=$(openssl x509 -in "$file" -text -noout 2>/dev/null)
      ;;
    *)
      error "Cannot show full details for this file type"
      return 1
      ;;
  esac

  if [[ -n "$output" ]]; then
    if is_interactive && command -v less &>/dev/null; then
      echo "$output" | less
    else
      echo "$output"
    fi
  fi
}

cmd_verify() {
  local cert="$1"
  local ca="$2"

  require_file "$cert" "Certificate"
  require_file "$ca" "CA bundle"

  step "Verifying certificate chain..."

  local result
  result=$(openssl verify -CAfile "$ca" "$cert" 2>&1) || true

  if [[ "$result" == *": OK"* ]]; then
    success "Certificate chain verified"
    return 0
  else
    error "Chain verification failed"
    echo
    # Show the actual error
    dim "openssl verify output:"
    while IFS= read -r line; do
      printf '  %s\n' "$line"
    done <<< "$result"
    echo

    # Check for common issues and provide hints
    if [[ "$result" == *"expired"* ]] || [[ "$result" == *"Expire"* ]]; then
      warn "Certificate or CA has expired"
      echo
      dim "Certificate expiry:"
      openssl x509 -in "$cert" -noout -dates 2>/dev/null | sed 's/^/  /'
      echo
      dim "CA expiry:"
      openssl x509 -in "$ca" -noout -dates 2>/dev/null | sed 's/^/  /'
    elif [[ "$result" == *"unable to get local issuer"* ]]; then
      # Show what we're looking for
      local cert_issuer ca_subject
      cert_issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
      ca_subject=$(openssl x509 -in "$ca" -noout -subject 2>/dev/null | sed 's/^subject=//')
      echo
      warn "Certificate issuer not found in CA bundle"
      dim "  Certificate was issued by:"
      dim "    $cert_issuer"
      dim "  CA bundle contains:"
      dim "    $ca_subject"
      echo
      info "The CA file must contain the issuer's certificate (or chain to root)"
    elif [[ "$result" == *"self"*"signed"* ]] || [[ "$result" == *"self-signed"* ]]; then
      info "Certificate is self-signed (verify against itself or skip verification)"
    fi
    return 1
  fi
}

cmd_match() {
  local cert="$1"
  local key="$2"

  require_file "$cert" "Certificate"
  require_file "$key" "Private key"

  step "Checking if key matches certificate..."

  if key_matches_cert "$cert" "$key"; then
    success "Private key matches certificate"
    return 0
  else
    error "Private key does NOT match certificate"
    return 1
  fi
}

cmd_expiry() {
  local cert="$1"
  local days="${2:-30}"

  require_file "$cert" "Certificate"

  local file_type
  file_type=$(detect_type "$cert")

  local expiry_date
  case "$file_type" in
    der)
      expiry_date=$(openssl x509 -in "$cert" -inform DER -noout -enddate 2>/dev/null | cut -d= -f2)
      ;;
    *)
      expiry_date=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
      ;;
  esac

  info "Expiration: $expiry_date"

  if openssl x509 -in "$cert" -checkend $((days * 86400)) -noout 2>/dev/null; then
    success "Certificate valid for at least $days more days"
    return 0
  else
    warn "Certificate expires within $days days (or already expired)"
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Convert Commands
# ═══════════════════════════════════════════════════════════════════════════════

cmd_to_pfx() {
  local cert="$1"
  local key="$2"
  local output="$3"
  local password="${4:-}"
  local ca="${5:-}"

  require_file "$cert" "Certificate"
  require_file "$key" "Private key"

  step "Validating certificate..."
  validate_pem_cert "$cert" || return 1

  step "Validating private key..."
  validate_pem_key "$key" || return 1

  step "Checking key matches certificate..."
  if ! key_matches_cert "$cert" "$key"; then
    error "Private key does NOT match certificate"
    return 1
  fi
  success "Key matches certificate"

  local cmd_args=(-export -out "$output" -inkey "$key" -in "$cert")

  if [[ -n "$ca" && -f "$ca" ]]; then
    step "Including CA bundle..."
    cmd_args+=(-certfile "$ca")
  fi

  cmd_args+=(-passout "pass:${password}")

  step "Creating PFX..."
  if openssl pkcs12 "${cmd_args[@]}" 2>/dev/null; then
    success "Created: $output"
    return 0
  else
    error "Failed to create PFX"
    return 1
  fi
}

cmd_from_pfx() {
  local input="$1"
  local output_dir="$2"
  local password="${3:-}"

  require_file "$input" "PFX file"

  step "Validating PFX..."
  validate_pfx "$input" "$password" || return 1

  mkdir -p "$output_dir"

  local basename
  basename=$(basename "$input" | sed 's/\.[^.]*$//')

  local cert_out="$output_dir/${basename}.crt"
  local key_out="$output_dir/${basename}.key"
  local ca_out="$output_dir/${basename}-ca.crt"

  local pass_args=(-passin "pass:${password}")

  step "Extracting certificate..."
  if openssl pkcs12 -in "$input" -clcerts -nokeys "${pass_args[@]}" -out "$cert_out" 2>/dev/null; then
    success "Certificate: $cert_out"
  else
    error "Failed to extract certificate"
    return 1
  fi

  step "Extracting private key..."
  if openssl pkcs12 -in "$input" -nocerts -nodes "${pass_args[@]}" -out "$key_out" 2>/dev/null; then
    chmod 600 "$key_out"
    success "Private key: $key_out (mode 600)"
  else
    error "Failed to extract private key"
    return 1
  fi

  step "Extracting CA certificates..."
  if openssl pkcs12 -in "$input" -cacerts -nokeys "${pass_args[@]}" -out "$ca_out" 2>/dev/null; then
    if [[ -s "$ca_out" ]] && grep -q "BEGIN CERTIFICATE" "$ca_out"; then
      success "CA bundle: $ca_out"
    else
      rm -f "$ca_out"
      dim "No CA certificates in PFX"
    fi
  fi
}

cmd_to_der() {
  local input="$1"
  local output="$2"
  local type="${3:-cert}"

  require_file "$input" "Input file"

  step "Converting to DER..."

  local result
  if [[ "$type" == "key" ]]; then
    validate_pem_key "$input" || return 1
    result=$(openssl rsa -in "$input" -inform PEM -out "$output" -outform DER 2>&1) || true
    if [[ -f "$output" ]] && [[ -s "$output" ]]; then
      success "Created: $output"
      return 0
    fi
  else
    validate_pem_cert "$input" || return 1
    result=$(openssl x509 -in "$input" -inform PEM -out "$output" -outform DER 2>&1) || true
    if [[ -f "$output" ]] && [[ -s "$output" ]]; then
      success "Created: $output"
      return 0
    fi
  fi

  error "Conversion to DER failed"
  [[ -n "$result" ]] && dim "  $result"
  return 1
}

cmd_from_der() {
  local input="$1"
  local output="$2"
  local type="${3:-cert}"

  require_file "$input" "DER file"

  if ! is_der_encoded "$input"; then
    warn "File may not be DER encoded (doesn't start with ASN.1 SEQUENCE tag)"
    is_interactive && ! confirm "Continue anyway?" && return 1
  fi

  step "Converting to PEM..."

  local result
  if [[ "$type" == "key" ]]; then
    result=$(openssl rsa -in "$input" -inform DER -out "$output" -outform PEM 2>&1) || true
    if [[ -f "$output" ]] && [[ -s "$output" ]]; then
      chmod 600 "$output"
      success "Created: $output"
      return 0
    fi
  else
    result=$(openssl x509 -in "$input" -inform DER -out "$output" -outform PEM 2>&1) || true
    if [[ -f "$output" ]] && [[ -s "$output" ]]; then
      success "Created: $output"
      return 0
    fi
  fi

  error "Conversion from DER failed"
  if [[ -n "$result" ]]; then
    dim "  $result"
  fi
  if [[ "$type" == "cert" ]]; then
    info "  Try with --key if this is a private key"
  else
    info "  Try without --key if this is a certificate"
  fi
  return 1
}

cmd_to_base64() {
  local input="$1"
  local output="$2"

  require_file "$input" "Input file"

  step "Encoding to Base64..."
  # macOS base64 uses -i, GNU base64 reads from stdin
  if base64 -i "$input" 2>/dev/null | tr -d '\n' > "$output" || \
     cat "$input" | base64 | tr -d '\n' > "$output"; then
    success "Created: $output"
    return 0
  else
    error "Encoding failed"
    return 1
  fi
}

cmd_from_base64() {
  local input="$1"
  local output="$2"

  require_file "$input" "Base64 file"

  step "Decoding Base64..."
  local content
  content=$(cat "$input")

  # Check for obviously invalid base64
  if [[ "$content" == *"-----BEGIN"* ]]; then
    error "File appears to be PEM format, not raw Base64"
    info "  PEM files are already text - no decoding needed"
    return 1
  fi

  if printf '%s' "$content" | base64 --decode > "$output" 2>/dev/null || \
     printf '%s' "$content" | base64 -d > "$output" 2>/dev/null || \
     printf '%s' "$content" | base64 -D > "$output" 2>/dev/null; then
    if [[ -s "$output" ]]; then
      success "Created: $output"
      return 0
    fi
  fi

  error "Base64 decoding failed"
  info "  File may contain invalid Base64 characters"
  return 1
}

cmd_combine() {
  local cert="$1"
  local key="$2"
  local output="$3"
  local ca="${4:-}"

  require_file "$cert" "Certificate"
  require_file "$key" "Private key"

  step "Validating files..."
  validate_pem_cert "$cert" || return 1
  validate_pem_key "$key" || return 1

  if ! key_matches_cert "$cert" "$key"; then
    error "Private key does NOT match certificate"
    return 1
  fi
  success "Key matches certificate"

  step "Creating combined PEM..."
  {
    cat "$cert"
    echo
    cat "$key"
    if [[ -n "$ca" && -f "$ca" ]]; then
      echo
      cat "$ca"
    fi
  } > "$output"

  chmod 600 "$output"
  success "Created: $output"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Generate Commands
# ═══════════════════════════════════════════════════════════════════════════════

cmd_csr() {
  local key_out="$1"
  local csr_out="$2"
  local cn="$3"
  local org="$4"
  local city="$5"
  local state="$6"
  local country="$7"
  local san="${8:-}"
  local org_unit="${9:-}"
  local key_size="${10:-2048}"

  [[ -z "$cn" || -z "$org" || -z "$city" || -z "$state" || -z "$country" ]] && \
    die "CN, Organization, City, State, and Country are required"

  case "$key_size" in
    2048|4096) ;;
    *) die "Key size must be 2048 or 4096" ;;
  esac

  local subj="/C=${country}/ST=${state}/L=${city}/O=${org}"
  [[ -n "$org_unit" ]] && subj="${subj}/OU=${org_unit}"
  subj="${subj}/CN=${cn}"

  local -a csr_args=()
  if [[ -n "$san" ]]; then
    local san_list=""
    IFS=',' read -ra entries <<< "$san"
    for entry in "${entries[@]}"; do
      entry=$(printf '%s' "$entry" | xargs)
      [[ -z "$entry" ]] && continue
      [[ -z "$san_list" ]] && san_list="DNS:${entry}" || san_list="${san_list},DNS:${entry}"
    done
    [[ -n "$san_list" ]] && csr_args+=(-addext "subjectAltName=${san_list}")
  fi

  step "Generating private key..."
  if ! openssl genrsa -out "$key_out" "$key_size" >/dev/null 2>&1; then
    error "Failed to generate private key"
    return 1
  fi
  chmod 600 "$key_out"
  success "Key: $key_out"

  step "Generating CSR..."
  if openssl req -new -key "$key_out" -out "$csr_out" -subj "$subj" "${csr_args[@]}" >/dev/null 2>&1; then
    success "CSR: $csr_out"
    return 0
  else
    error "Failed to generate CSR"
    return 1
  fi
}

cmd_selfsign() {
  local key_out="$1"
  local cert_out="$2"
  local cn="$3"
  local org="$4"
  local city="$5"
  local state="$6"
  local country="$7"
  local san="${8:-}"
  local org_unit="${9:-}"
  local key_size="${10:-2048}"
  local days="${11:-365}"

  [[ -z "$cn" || -z "$org" || -z "$city" || -z "$state" || -z "$country" ]] && \
    die "CN, Organization, City, State, and Country are required"

  case "$key_size" in
    2048|4096) ;;
    *) die "Key size must be 2048 or 4096" ;;
  esac

  local subj="/C=${country}/ST=${state}/L=${city}/O=${org}"
  [[ -n "$org_unit" ]] && subj="${subj}/OU=${org_unit}"
  subj="${subj}/CN=${cn}"

  local -a addexts=()
  if [[ -n "$san" ]]; then
    local san_list=""
    IFS=',' read -ra entries <<< "$san"
    for entry in "${entries[@]}"; do
      entry=$(printf '%s' "$entry" | xargs)
      [[ -z "$entry" ]] && continue
      [[ -z "$san_list" ]] && san_list="DNS:${entry}" || san_list="${san_list},DNS:${entry}"
    done
    [[ -n "$san_list" ]] && addexts+=(-addext "subjectAltName=${san_list}")
  fi
  addexts+=(-addext "keyUsage=digitalSignature")
  addexts+=(-addext "extendedKeyUsage=serverAuth")

  step "Generating self-signed certificate..."
  if openssl req -x509 -nodes -days "$days" -newkey "rsa:${key_size}" \
       -keyout "$key_out" -out "$cert_out" -subj "$subj" "${addexts[@]}" >/dev/null 2>&1; then
    chmod 600 "$key_out"
    success "Key: $key_out"
    success "Certificate: $cert_out"
    return 0
  else
    error "Failed to generate certificate"
    return 1
  fi
}

cmd_mkcert() {
  local cert_out="$1"
  local key_out="$2"
  local domains="$3"

  if ! command -v mkcert >/dev/null 2>&1; then
    die "mkcert is not installed (brew install mkcert)"
  fi

  [[ -z "$domains" ]] && die "At least one domain is required"

  local -a domain_args=()
  IFS=',' read -ra entries <<< "$domains"
  for entry in "${entries[@]}"; do
    entry=$(printf '%s' "$entry" | xargs)
    [[ -n "$entry" ]] && domain_args+=("$entry")
  done

  [[ ${#domain_args[@]} -eq 0 ]] && die "At least one domain is required"

  step "Generating certificate with mkcert..."
  if mkcert -cert-file "$cert_out" -key-file "$key_out" "${domain_args[@]}" >/dev/null 2>&1; then
    success "Certificate: $cert_out"
    success "Key: $key_out"
    return 0
  else
    error "mkcert failed"
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Interactive Mode
# ═══════════════════════════════════════════════════════════════════════════════

interactive_main() {
  local file="${1:-}"

  if ! has_fzf; then
    die "fzf is required for interactive mode (brew install fzf)"
  fi

  while true; do
    echo
    msg "${BOLD}${CYAN}certconv${NC} ${DIM}v${VERSION}${NC}"
    echo

    # File selection
    if [[ -z "$file" ]]; then
      file=$(pick_file "Select a certificate file") || {
        dim "No file selected. Exiting."
        return 0
      }
    fi

    # Show file info
    cmd_show "$file" ""

    # Get available actions based on file type
    local file_type
    file_type=$(detect_type "$file")

    local -a actions=()
    # Common actions for all file types
    actions+=("View contents" "Copy to clipboard" "Copy to clipboard (no linebreaks)")
    actions+=("---")

    case "$file_type" in
      cert|combined)
        actions+=("Full details" "Check expiry" "Verify chain" "Check key match")
        actions+=("Convert to PFX" "Convert to DER" "Encode to Base64" "Combine with key")
        ;;
      pfx|p12)
        actions+=("Full details" "Extract to PEM" "Encode to Base64")
        ;;
      der)
        actions+=("Full details" "Check expiry" "Convert to PEM" "Encode to Base64")
        ;;
      key)
        actions+=("Convert to DER" "Encode to Base64" "Combine with cert")
        ;;
      base64)
        actions+=("Decode Base64")
        ;;
      *)
        actions+=("Encode to Base64")
        ;;
    esac
    actions+=("---" "Pick another file" "Generate new..." "Exit")

    local action
    action=$(pick_option "Choose action" "${actions[@]}") || {
      file=""
      continue
    }

    echo
    case "$action" in
      "View contents")
        cmd_view "$file"
        ;;
      "Copy to clipboard")
        cmd_copy "$file"
        ;;
      "Copy to clipboard (no linebreaks)")
        cmd_copy_oneline "$file"
        ;;
      "Full details")
        cmd_show_full "$file" ""
        ;;
      "Check expiry")
        local days
        days=$(read_value "Days to check" "30") || continue
        cmd_expiry "$file" "$days"
        ;;
      "Verify chain")
        local ca
        ca=$(pick_file "Select CA bundle") || continue
        cmd_verify "$file" "$ca"
        ;;
      "Check key match")
        local key
        key=$(pick_file "Select private key" "key,pem") || continue
        cmd_match "$file" "$key"
        ;;
      "Convert to PFX")
        local key output password ca=""
        key=$(pick_file "Select private key" "key,pem") || continue
        output=$(read_value "Output filename" "certificate.pfx") || continue
        if confirm "Set export password?"; then
          password=$(read_value "Password" "" true) || continue
        else
          password=""
        fi
        if confirm "Include CA bundle?"; then
          ca=$(pick_file "Select CA bundle") || true
        fi
        cmd_to_pfx "$file" "$key" "$output" "$password" "$ca"
        ;;
      "Convert to DER")
        local output
        output=$(read_value "Output filename" "certificate.der") || continue
        cmd_to_der "$file" "$output" "cert"
        ;;
      "Encode to Base64")
        local output
        output=$(read_value "Output filename" "${file}.base64") || continue
        cmd_to_base64 "$file" "$output"
        ;;
      "Combine with key"|"Combine with cert")
        local cert key output ca=""
        if [[ "$file_type" == "key" ]]; then
          key="$file"
          cert=$(pick_file "Select certificate" "crt,cer,pem") || continue
        else
          cert="$file"
          key=$(pick_file "Select private key" "key,pem") || continue
        fi
        output=$(read_value "Output filename" "combined.pem") || continue
        if confirm "Include CA bundle?"; then
          ca=$(pick_file "Select CA bundle") || true
        fi
        cmd_combine "$cert" "$key" "$output" "$ca"
        ;;
      "Extract to PEM")
        local output_dir password=""
        output_dir=$(read_value "Output directory" ".") || continue
        if confirm "Is the PFX password protected?"; then
          password=$(read_value "Password" "" true) || continue
        fi
        cmd_from_pfx "$file" "$output_dir" "$password"
        ;;
      "Convert to PEM")
        local output
        output=$(read_value "Output filename" "certificate.pem") || continue
        cmd_from_der "$file" "$output" "cert"
        ;;
      "Decode Base64")
        local output
        output=$(read_value "Output filename" "${file}.decoded") || continue
        cmd_from_base64 "$file" "$output"
        ;;
      "Pick another file")
        file=""
        ;;
      "Generate new...")
        interactive_generate
        ;;
      "---")
        continue
        ;;
      "Exit")
        dim "Goodbye!"
        return 0
        ;;
    esac

    echo
    if ! confirm "Continue?"; then
      dim "Goodbye!"
      return 0
    fi
    file=""
  done
}

interactive_generate() {
  local -a options=("CSR (Certificate Signing Request)" "Self-signed certificate")
  command -v mkcert &>/dev/null && options+=("Local dev cert (mkcert)")
  options+=("Cancel")

  local choice
  choice=$(pick_option "What to generate?" "${options[@]}") || return

  case "$choice" in
    "CSR"*)
      local cn org city state country san org_unit key_size key_out csr_out
      cn=$(read_value "Common Name (FQDN)") || return
      [[ -z "$cn" ]] && { error "CN is required"; return; }
      san=$(read_value "SANs (comma-separated, optional)" "") || return
      org=$(read_value "Organization") || return
      org_unit=$(read_value "Department (optional)" "") || return
      city=$(read_value "City") || return
      state=$(read_value "State/Province") || return
      country=$(read_value "Country (2-letter)") || return
      key_size=$(pick_option "Key size" "2048" "4096") || return
      key_out=$(read_value "Key filename" "private.key") || return
      csr_out=$(read_value "CSR filename" "request.csr") || return
      cmd_csr "$key_out" "$csr_out" "$cn" "$org" "$city" "$state" "$country" "$san" "$org_unit" "$key_size"
      ;;
    "Self-signed"*)
      local cn org city state country san org_unit key_size days key_out cert_out
      cn=$(read_value "Common Name (FQDN)") || return
      [[ -z "$cn" ]] && { error "CN is required"; return; }
      san=$(read_value "SANs (comma-separated, optional)" "") || return
      org=$(read_value "Organization") || return
      org_unit=$(read_value "Department (optional)" "") || return
      city=$(read_value "City") || return
      state=$(read_value "State/Province") || return
      country=$(read_value "Country (2-letter)") || return
      key_size=$(pick_option "Key size" "2048" "4096") || return
      days=$(read_value "Validity (days)" "365") || return
      key_out=$(read_value "Key filename" "private.key") || return
      cert_out=$(read_value "Certificate filename" "certificate.crt") || return
      cmd_selfsign "$key_out" "$cert_out" "$cn" "$org" "$city" "$state" "$country" "$san" "$org_unit" "$key_size" "$days"
      ;;
    "Local dev"*)
      local domains cert_out key_out
      domains=$(read_value "Domains (comma-separated)" "localhost") || return
      cert_out=$(read_value "Certificate filename" "cert.pem") || return
      key_out=$(read_value "Key filename" "key.pem") || return
      cmd_mkcert "$cert_out" "$key_out" "$domains"
      ;;
    *)
      return
      ;;
  esac
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

show_usage() {
  cat <<EOF
${BOLD}certconv${NC} v${VERSION} - Certificate conversion tool

${BOLD}USAGE${NC}
  $SCRIPT_NAME                      Interactive mode (requires fzf)
  $SCRIPT_NAME FILE                 Interactive with file pre-selected
  $SCRIPT_NAME COMMAND [args]       Run command directly

${BOLD}INFO COMMANDS${NC} (non-invasive)
  show FILE                   Show certificate summary
  show-full FILE              Show full certificate details
  verify CERT CA              Verify certificate chain
  match CERT KEY              Check if key matches certificate
  expiry CERT [DAYS]          Check certificate expiration (default: 30 days)

${BOLD}CONVERT COMMANDS${NC}
  to-pfx CERT KEY OUT [-p PW] [-a CA]    Convert PEM to PFX
  from-pfx INPUT OUTDIR [-p PW]          Extract PEM from PFX
  to-der INPUT OUTPUT [--key]            Convert PEM to DER
  from-der INPUT OUTPUT [--key]          Convert DER to PEM
  to-base64 INPUT OUTPUT                 Encode file to Base64
  from-base64 INPUT OUTPUT               Decode Base64 to file
  combine CERT KEY OUTPUT [-a CA]        Combine cert + key into single PEM

${BOLD}GENERATE COMMANDS${NC}
  csr --cn NAME --org ORG --city CITY --state ST --country CC [options]
  selfsign --cn NAME --org ORG --city CITY --state ST --country CC [options]
  mkcert --domains DOMAINS [-o CERT] [-k KEY]

${BOLD}OPTIONS${NC}
  -p, --password    PFX password
  -a, --ca          CA bundle file
  -o, --output      Output file
  -k, --key         Key file (for generate commands: output key path)
  --cn              Common Name (FQDN)
  --san             Subject Alternative Names (comma-separated)
  --org             Organization
  --org-unit        Department (optional)
  --city            City/Locality
  --state           State/Province
  --country         Country (2-letter code)
  --key-size        Key size: 2048 or 4096 (default: 2048)
  --days            Validity in days (default: 365)
  --domains         Domains for mkcert (comma-separated)
  -n, --non-interactive   Disable interactive prompts
  -h, --help        Show this help

${BOLD}EXAMPLES${NC}
  $SCRIPT_NAME                                    # Interactive mode
  $SCRIPT_NAME cert.pem                           # Interactive with file
  $SCRIPT_NAME show cert.pem                      # Show cert info
  $SCRIPT_NAME verify cert.pem ca.pem             # Verify chain
  $SCRIPT_NAME to-pfx cert.pem key.pem out.pfx    # Create PFX
  $SCRIPT_NAME from-pfx bundle.pfx ./extracted    # Extract from PFX
  $SCRIPT_NAME selfsign --cn app.local --org "Dev" --city "NYC" --state "NY" --country "US"

${BOLD}ENVIRONMENT${NC}
  CERTCONV_NONINTERACTIVE=true    Disable interactive mode
  CERTCONV_CERTS_DIR=./certs      Default directory for file picker
EOF
}

main() {
  # Check openssl
  command -v openssl &>/dev/null || die "openssl is required but not found"

  # No args = interactive
  if [[ $# -eq 0 ]]; then
    interactive_main ""
    return
  fi

  # Parse first arg
  local cmd="$1"
  shift

  case "$cmd" in
    -h|--help)
      show_usage
      return 0
      ;;
    -n|--non-interactive)
      CERTCONV_NONINTERACTIVE=true
      if [[ $# -gt 0 ]]; then
        main "$@"
      fi
      return
      ;;

    # Info commands
    show)
      [[ $# -lt 1 ]] && die "Usage: $SCRIPT_NAME show FILE"
      cmd_show "$(resolve_path "$1")" "${2:-}"
      ;;
    show-full)
      [[ $# -lt 1 ]] && die "Usage: $SCRIPT_NAME show-full FILE"
      cmd_show_full "$(resolve_path "$1")" "${2:-}"
      ;;
    verify)
      [[ $# -lt 2 ]] && die "Usage: $SCRIPT_NAME verify CERT CA"
      cmd_verify "$(resolve_path "$1")" "$(resolve_path "$2")"
      ;;
    match)
      [[ $# -lt 2 ]] && die "Usage: $SCRIPT_NAME match CERT KEY"
      cmd_match "$(resolve_path "$1")" "$(resolve_path "$2")"
      ;;
    expiry)
      [[ $# -lt 1 ]] && die "Usage: $SCRIPT_NAME expiry CERT [DAYS]"
      cmd_expiry "$(resolve_path "$1")" "${2:-30}"
      ;;

    # Convert commands
    to-pfx)
      local cert="" key="" output="" password="" ca=""
      while [[ $# -gt 0 ]]; do
        case "$1" in
          -p|--password) password="$2"; shift 2 ;;
          -a|--ca) ca="$2"; shift 2 ;;
          *)
            if [[ -z "$cert" ]]; then cert="$1"
            elif [[ -z "$key" ]]; then key="$1"
            elif [[ -z "$output" ]]; then output="$1"
            fi
            shift
            ;;
        esac
      done
      [[ -z "$cert" || -z "$key" || -z "$output" ]] && die "Usage: $SCRIPT_NAME to-pfx CERT KEY OUTPUT [-p PW] [-a CA]"
      cmd_to_pfx "$(resolve_path "$cert")" "$(resolve_path "$key")" "$output" "$password" "$(resolve_path "$ca")"
      ;;

    from-pfx)
      local input="" output_dir="" password=""
      while [[ $# -gt 0 ]]; do
        case "$1" in
          -p|--password) password="$2"; shift 2 ;;
          *)
            if [[ -z "$input" ]]; then input="$1"
            elif [[ -z "$output_dir" ]]; then output_dir="$1"
            fi
            shift
            ;;
        esac
      done
      [[ -z "$input" || -z "$output_dir" ]] && die "Usage: $SCRIPT_NAME from-pfx INPUT OUTDIR [-p PW]"
      cmd_from_pfx "$(resolve_path "$input")" "$output_dir" "$password"
      ;;

    to-der)
      local input="" output="" type="cert"
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --key) type="key"; shift ;;
          *)
            if [[ -z "$input" ]]; then input="$1"
            elif [[ -z "$output" ]]; then output="$1"
            fi
            shift
            ;;
        esac
      done
      [[ -z "$input" || -z "$output" ]] && die "Usage: $SCRIPT_NAME to-der INPUT OUTPUT [--key]"
      cmd_to_der "$(resolve_path "$input")" "$output" "$type"
      ;;

    from-der)
      local input="" output="" type="cert"
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --key) type="key"; shift ;;
          *)
            if [[ -z "$input" ]]; then input="$1"
            elif [[ -z "$output" ]]; then output="$1"
            fi
            shift
            ;;
        esac
      done
      [[ -z "$input" || -z "$output" ]] && die "Usage: $SCRIPT_NAME from-der INPUT OUTPUT [--key]"
      cmd_from_der "$(resolve_path "$input")" "$output" "$type"
      ;;

    to-base64)
      [[ $# -lt 2 ]] && die "Usage: $SCRIPT_NAME to-base64 INPUT OUTPUT"
      cmd_to_base64 "$(resolve_path "$1")" "$2"
      ;;

    from-base64)
      [[ $# -lt 2 ]] && die "Usage: $SCRIPT_NAME from-base64 INPUT OUTPUT"
      cmd_from_base64 "$(resolve_path "$1")" "$2"
      ;;

    combine)
      local cert="" key="" output="" ca=""
      while [[ $# -gt 0 ]]; do
        case "$1" in
          -a|--ca) ca="$2"; shift 2 ;;
          *)
            if [[ -z "$cert" ]]; then cert="$1"
            elif [[ -z "$key" ]]; then key="$1"
            elif [[ -z "$output" ]]; then output="$1"
            fi
            shift
            ;;
        esac
      done
      [[ -z "$cert" || -z "$key" || -z "$output" ]] && die "Usage: $SCRIPT_NAME combine CERT KEY OUTPUT [-a CA]"
      cmd_combine "$(resolve_path "$cert")" "$(resolve_path "$key")" "$output" "$(resolve_path "$ca")"
      ;;

    # Generate commands
    csr)
      local cn="" san="" org="" org_unit="" city="" state="" country="" key_size="2048" key_out="private.key" csr_out="request.csr"
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --cn) cn="$2"; shift 2 ;;
          --san) san="$2"; shift 2 ;;
          --org) org="$2"; shift 2 ;;
          --org-unit) org_unit="$2"; shift 2 ;;
          --city) city="$2"; shift 2 ;;
          --state) state="$2"; shift 2 ;;
          --country) country="$2"; shift 2 ;;
          --key-size) key_size="$2"; shift 2 ;;
          -k|--key) key_out="$2"; shift 2 ;;
          -o|--output) csr_out="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      cmd_csr "$key_out" "$csr_out" "$cn" "$org" "$city" "$state" "$country" "$san" "$org_unit" "$key_size"
      ;;

    selfsign)
      local cn="" san="" org="" org_unit="" city="" state="" country="" key_size="2048" days="365"
      local key_out="private.key" cert_out="certificate.crt"
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --cn) cn="$2"; shift 2 ;;
          --san) san="$2"; shift 2 ;;
          --org) org="$2"; shift 2 ;;
          --org-unit) org_unit="$2"; shift 2 ;;
          --city) city="$2"; shift 2 ;;
          --state) state="$2"; shift 2 ;;
          --country) country="$2"; shift 2 ;;
          --key-size) key_size="$2"; shift 2 ;;
          --days) days="$2"; shift 2 ;;
          -k|--key) key_out="$2"; shift 2 ;;
          -o|--output) cert_out="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      cmd_selfsign "$key_out" "$cert_out" "$cn" "$org" "$city" "$state" "$country" "$san" "$org_unit" "$key_size" "$days"
      ;;

    mkcert)
      local domains="" cert_out="cert.pem" key_out="key.pem"
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --domains) domains="$2"; shift 2 ;;
          -o|--output) cert_out="$2"; shift 2 ;;
          -k|--key) key_out="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      cmd_mkcert "$cert_out" "$key_out" "$domains"
      ;;

    # Default: treat as file for interactive mode
    *)
      if [[ -f "$cmd" || -f "$(resolve_path "$cmd")" ]]; then
        interactive_main "$(resolve_path "$cmd")"
      else
        error "Unknown command: $cmd"
        echo
        show_usage
        exit 1
      fi
      ;;
  esac
}

main "$@"
