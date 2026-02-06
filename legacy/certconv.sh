#!/usr/bin/env bash
# shellcheck shell=bash
#
# certconv - A certificate conversion tool with optional TUI enhancement
#
# Convert between PEM, PFX/P12, CRT, KEY, DER, and more with
# defensive validation. Uses gum for enhanced UI when available,
# falls back gracefully to plain terminal.
#
# Requirements: openssl
# Optional: gum (https://github.com/charmbracelet/gum)
#

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

VERSION="1.1.0"
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Environment overrides
CERTCONV_NONINTERACTIVE="${CERTCONV_NONINTERACTIVE:-false}"
CERTCONV_ASSUME_YES="${CERTCONV_ASSUME_YES:-false}"
CERTCONV_FORCE_GUM="${CERTCONV_FORCE_GUM:-false}"
CERTCONV_MIN_OPENSSL_VERSION="${CERTCONV_MIN_OPENSSL_VERSION:-1.1.1}"
CERTCONV_MIN_LIBRESSL_VERSION="${CERTCONV_MIN_LIBRESSL_VERSION:-3.0.0}"
CERTCONV_CERTS_DIR="${CERTCONV_CERTS_DIR:-./certs}"

TEMP_FILES=()

# Colors (used when gum unavailable)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════════════════════════
# UI Abstraction Layer (gum optional)
# ═══════════════════════════════════════════════════════════════════════════════

ui_has_gum() {
  command -v gum &>/dev/null
}

ui_is_interactive() {
  if _is_true "${CERTCONV_NONINTERACTIVE}"; then
    return 1
  fi
  # Interactive only when stdin is a TTY
  [[ -t 0 ]]
}

ui_use_gum() {
  (_is_true "${CERTCONV_FORCE_GUM}" || ui_is_interactive) && ui_has_gum
}

_is_true() {
  local val="${1:-}"
  val=$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')
  [[ "$val" =~ ^(true|yes|1)$ ]]
}

_lowercase() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'
}

resolve_input_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    printf '%s\n' "$path"
    return 0
  fi

  if [[ -f "$path" || "$path" == */* || "$path" == ./* || "$path" == ~* || "$path" == /* ]]; then
    printf '%s\n' "$path"
    return 0
  fi

  local certs_dir
  certs_dir=$(resolve_certs_dir "$CERTCONV_CERTS_DIR")
  local candidate="${certs_dir%/}/$path"
  if [[ -f "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  printf '%s\n' "$path"
}

resolve_certs_dir() {
  local dir="$1"
  if [[ -z "$dir" ]]; then
    printf '%s\n' "$dir"
    return 0
  fi

  if [[ "$dir" == /* || "$dir" == ~* || "$dir" == ./* ]]; then
    printf '%s\n' "$dir"
    return 0
  fi

  printf '%s\n' "${SCRIPT_DIR%/}/$dir"
}

dir_has_files() {
  local dir="$1"
  [[ -d "$dir" ]] || return 1
  find "$dir" -maxdepth 1 -type f -print -quit 2>/dev/null | grep -q .
}

register_temp_file() {
  local file="$1"
  [[ -n "$file" ]] && TEMP_FILES+=("$file")
}

cleanup_temp_files() {
  local file
  if ((${#TEMP_FILES[@]})); then
    for file in "${TEMP_FILES[@]}"; do
      [[ -n "$file" ]] && rm -f "$file"
    done
  fi
  return 0
}

_print_tty() {
  printf '%s\n' "$*" >/dev/tty 2>/dev/null || printf '%s\n' "$*" >&2
}

_read_line() {
  local __out_var="${1:?out var required}"
  local line

  if [[ -t 0 && -r /dev/tty ]]; then
    IFS= read -r line </dev/tty || return 1
  else
    IFS= read -r line || return 1
  fi

  printf -v "${__out_var}" '%s' "${line}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Styled Output
# ─────────────────────────────────────────────────────────────────────────────

ui_header() {
  local title="$1"
  local subtitle="${2:-}"

  if ui_use_gum; then
    if [[ -n "$subtitle" ]]; then
      gum style \
        --foreground 135 \
        --border-foreground 135 \
        --border double \
        --align center \
        --width 60 \
        --margin "1 2" \
        --padding "1 4" \
        "$title" "$subtitle"
    else
      gum style \
        --foreground 135 \
        --border-foreground 135 \
        --border double \
        --align center \
        --width 60 \
        --margin "1 2" \
        --padding "1 4" \
        "$title"
    fi
  else
    echo ""
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}${BOLD}  $title${NC}"
    [[ -n "$subtitle" ]] && echo -e "${PURPLE}  $subtitle${NC}"
    echo -e "${PURPLE}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo ""
  fi
}

ui_success() {
  if ui_use_gum; then
    gum style --foreground 82 "✅ $1"
  else
    echo -e "${GREEN}✅ $1${NC}"
  fi
}

ui_error() {
  if ui_use_gum; then
    gum style --foreground 196 "❌ $1"
  else
    echo -e "${RED}❌ $1${NC}" >&2
  fi
}

ui_warning() {
  if ui_use_gum; then
    gum style --foreground 214 "⚠️  $1"
  else
    echo -e "${YELLOW}⚠️  $1${NC}"
  fi
}

ui_info() {
  if ui_use_gum; then
    gum style --foreground 39 "ℹ️  $1"
  else
    echo -e "${BLUE}ℹ️  $1${NC}"
  fi
}

ui_step() {
  if ui_use_gum; then
    gum style --foreground 245 "→ $1"
  else
    echo -e "${GRAY}→ $1${NC}"
  fi
}

ui_dim() {
  if ui_use_gum; then
    gum style --foreground 245 "$1"
  else
    echo -e "${GRAY}$1${NC}"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Interactive Prompts
# ─────────────────────────────────────────────────────────────────────────────

ui_choose() {
  local prompt="${1:?prompt required}"
  shift
  local -a items=("$@")

  if [[ ${#items[@]} -eq 0 ]]; then
    ui_error "No items to select from"
    return 1
  fi

  if [[ ${#items[@]} -eq 1 ]]; then
    printf '%s\n' "${items[0]}"
    return 0
  fi

  if _is_true "${CERTCONV_NONINTERACTIVE}"; then
    ui_error "Multiple choices available but CERTCONV_NONINTERACTIVE=true"
    return 1
  fi

  if ui_use_gum; then
    gum choose --header "${prompt}" --cursor.foreground 135 "${items[@]}"
    return $?
  fi

  _print_tty ""
  _print_tty "$prompt"
  _print_tty ""
  local i=1
  for item in "${items[@]}"; do
    _print_tty "  ${i}. ${item}"
    ((i++))
  done
  _print_tty ""

  local selection=""
  while true; do
    _print_tty "Enter selection (1-${#items[@]}): "
    if ! _read_line selection; then
      ui_error "No input available (EOF)"
      return 1
    fi

    if [[ -z "${selection}" ]]; then
      _print_tty "Selection is required"
      continue
    fi

    if [[ "${selection}" =~ ^[0-9]+$ ]] && ((selection >= 1 && selection <= ${#items[@]})); then
      printf '%s\n' "${items[$((selection - 1))]}"
      return 0
    fi

    _print_tty "Invalid selection"
  done
}

ui_confirm() {
  local prompt="${1:-Continue?}"

  if _is_true "${CERTCONV_ASSUME_YES}"; then
    return 0
  fi

  if _is_true "${CERTCONV_NONINTERACTIVE}"; then
    return 1
  fi

  if ui_use_gum; then
    gum confirm "$prompt"
    return $?
  fi

  local answer=""
  _print_tty "${prompt} [y/N]: "
  if ! _read_line answer; then
    return 1
  fi
  answer=$(_lowercase "$answer")

  [[ "${answer}" == "y" || "${answer}" == "yes" ]]
}

ui_input() {
  local prompt="${1:-Enter value}"
  local default="${2:-}"
  local password="${3:-false}"

  if _is_true "${CERTCONV_NONINTERACTIVE}"; then
    if [[ -n "$default" ]]; then
      printf '%s\n' "$default"
      return 0
    fi
    ui_error "Input required but CERTCONV_NONINTERACTIVE=true"
    return 1
  fi

  if ui_use_gum; then
    local args=(--placeholder "$prompt")
    [[ -n "$default" ]] && args+=(--value "$default")
    [[ "$password" == "true" ]] && args+=(--password)
    gum input "${args[@]}"
    return $?
  fi

  local value=""
  if [[ -n "$default" ]]; then
    _print_tty "${prompt} [$default]: "
  else
    _print_tty "${prompt}: "
  fi

  if [[ "$password" == "true" ]]; then
    read -rs value </dev/tty 2>/dev/null || read -rs value
    _print_tty "" # newline after hidden input
  else
    _read_line value || return 1
  fi

  if [[ -z "$value" && -n "$default" ]]; then
    value="$default"
  fi

  printf '%s\n' "$value"
}

ui_file_picker() {
  local prompt="${1:-Select file}"
  local mode="${2:-cert}"
  local default_dir
  default_dir=$(resolve_certs_dir "$CERTCONV_CERTS_DIR")

  if _is_true "${CERTCONV_NONINTERACTIVE}"; then
    ui_error "File picker requires interactive mode"
    return 1
  fi

  local -a exts=()
  case "$mode" in
  cert)
    exts=(cer pem der pfx)
    ;;
  key)
    exts=(key pem)
    ;;
  base64)
    exts=(base64 b64)
    ;;
  any)
    exts=()
    ;;
  *)
    exts=(cer pem der pfx)
    ;;
  esac

  file_picker_list() {
    local dir="$1"
    if [[ ${#exts[@]} -eq 0 ]]; then
      find "$dir" -maxdepth 1 -type f -print 2>/dev/null
      return 0
    fi
    local args=()
    local first=1
    local ext
    for ext in "${exts[@]}"; do
      if [[ $first -eq 0 ]]; then
        args+=(-o)
      fi
      args+=(-iname "*.${ext}")
      first=0
    done
    # shellcheck disable=SC2048
    find "$dir" -maxdepth 1 -type f \( "${args[@]}" \) -print 2>/dev/null
  }

  local start_dir="."
  if [[ -d "$default_dir" ]]; then
    start_dir="$default_dir"
  fi

  if ui_is_interactive && command -v fzf >/dev/null 2>&1; then
    local picked
    picked=$(file_picker_list "$start_dir" | sort | fzf --prompt "$prompt > " --height 15 --reverse) || return 1
    picked=$(resolve_input_path "$picked")
    printf '%s\n' "$picked"
    return 0
  fi

  if ui_use_gum; then
    local picked
    picked=$(gum file --file --height 15 "$start_dir") || return $?
    picked=$(resolve_input_path "$picked")
    printf '%s\n' "$picked"
    return 0
  fi

  # Fallback: list files and let user type path
  _print_tty ""
  _print_tty "$prompt"
  if [[ -d "$default_dir" ]]; then
    _print_tty "Default directory: $default_dir"
    file_picker_list "$default_dir" | head -20 | while IFS= read -r line; do
      _print_tty "  $line"
    done
  else
    _print_tty "Current directory: $(pwd)"
    file_picker_list "." | head -20 | while IFS= read -r line; do
      _print_tty "  $line"
    done
  fi
  _print_tty ""

  local filepath=""
  _print_tty "Enter file path: "
  _read_line filepath || return 1

  filepath=$(resolve_input_path "$filepath")
  printf '%s\n' "$filepath"
}

ui_spinner() {
  local title="$1"
  shift

  if ui_use_gum; then
    gum spin --spinner dot --title "$title" -- "$@"
  else
    _print_tty "$title"
    "$@"
  fi
}

ui_pager() {
  local content="$1"

  if ui_use_gum; then
    echo "$content" | gum pager --border rounded
  else
    echo "$content" | ${PAGER:-less}
  fi
}

ui_clear() {
  if ui_is_interactive && [[ -t 1 ]]; then
    if command -v tput >/dev/null 2>&1; then
      tput clear
    else
      printf '\033c'
    fi
  fi
}

ui_box() {
  local content="$1"

  if ui_use_gum; then
    gum style \
      --border rounded \
      --border-foreground 39 \
      --padding "1 2" \
      --margin "1 0" \
      "$content"
  else
    echo ""
    echo "┌──────────────────────────────────────────────────────────┐"
    while IFS= read -r line; do
      printf "│ %-58s │\n" "$line"
    done <<< "$content"
    echo "└──────────────────────────────────────────────────────────┘"
    echo ""
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Core Validation Functions
# ═══════════════════════════════════════════════════════════════════════════════

validate_file_exists() {
  local file="$1"
  local desc="${2:-File}"

  if [[ ! -f "$file" ]]; then
    ui_error "$desc not found: $file"
    return 1
  fi

  if [[ ! -r "$file" ]]; then
    ui_error "$desc is not readable: $file"
    return 1
  fi

  return 0
}

pem_strict_check() {
  local file="$1"
  local begin_re="$2"
  local end_re="$3"

  awk -v begin_re="$begin_re" -v end_re="$end_re" '
    BEGIN { in_block=0; b=0; e=0; bad=0 }
    {
      if ($0 ~ begin_re) { b++; if (in_block) bad=1; in_block=1; next }
      if ($0 ~ end_re) { e++; if (!in_block) bad=1; in_block=0; next }
      if (in_block) {
        if ($0 ~ /^[A-Za-z0-9+\/=]+$/) next
        if ($0 ~ /^$/) { bad=1; next }
        bad=1; next
      } else {
        if ($0 !~ /^$/) bad=1
      }
    }
    END {
      if (b != 1 || e != 1 || in_block || bad) exit 1
    }
  ' "$file"
}

normalize_pem() {
  local input="$1"
  local output="$2"
  local type="${3:-auto}"
  local quiet="${4:-false}"

  validate_file_exists "$input" "Input file" || return 1

  local begin_line label
  case "$type" in
  cert)
    begin_line=$(grep -m1 -E '^-----BEGIN CERTIFICATE-----$' "$input" 2>/dev/null || true)
    ;;
  key)
    begin_line=$(grep -m1 -E '^-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----$' "$input" 2>/dev/null || true)
    ;;
  auto | "")
    begin_line=$(grep -m1 -E '^-----BEGIN (CERTIFICATE|(RSA |EC |ENCRYPTED )?PRIVATE KEY)-----$' "$input" 2>/dev/null || true)
    ;;
  *)
    ui_error "Unknown normalize type: $type"
    return 1
    ;;
  esac

  if [[ -z "$begin_line" ]]; then
    ui_error "Could not find a PEM block to normalize: $input"
    return 1
  fi

  label="${begin_line#-----BEGIN }"
  label="${label%-----}"

  local begin_re="^-----BEGIN ${label}-----$"
  local end_re="^-----END ${label}-----$"

  local begin_count end_count begin_no end_no
  begin_count=$(grep -c -E "$begin_re" "$input" 2>/dev/null || true)
  end_count=$(grep -c -E "$end_re" "$input" 2>/dev/null || true)

  if [[ "$begin_count" -ne 1 || "$end_count" -ne 1 ]]; then
    ui_error "Expected exactly one PEM block (${label}); found ${begin_count} BEGIN and ${end_count} END"
    return 1
  fi

  begin_no=$(grep -n -m1 -E "$begin_re" "$input" | cut -d: -f1)
  end_no=$(grep -n -m1 -E "$end_re" "$input" | cut -d: -f1)
  if [[ -n "$begin_no" && -n "$end_no" && "$begin_no" -ge "$end_no" ]]; then
    ui_error "Malformed PEM block ordering for ${label}"
    return 1
  fi

  if ! awk -v begin_re="$begin_re" -v end_re="$end_re" '
    BEGIN { in_block=0; bad=0 }
    {
      if ($0 ~ begin_re) { in_block=1; next }
      if ($0 ~ end_re) { in_block=0; next }
      if (!in_block && $0 !~ /^[[:space:]]*$/) bad=1
    }
    END { exit bad }
  ' "$input"; then
    ui_error "Unexpected non-whitespace outside PEM block: $input"
    return 1
  fi

  local payload
  payload=$(awk -v begin_re="$begin_re" -v end_re="$end_re" '
    $0 ~ begin_re { in_block=1; next }
    $0 ~ end_re { in_block=0; exit }
    in_block { print }
  ' "$input" | tr -d '[:space:]')

  if [[ -z "$payload" ]]; then
    ui_error "Empty PEM payload: $input"
    return 1
  fi

  if ! [[ "$payload" =~ ^[A-Za-z0-9+/=]+$ ]]; then
    ui_error "Invalid base64 content in PEM payload: $input"
    return 1
  fi

  local out_dir
  out_dir=$(dirname "$output")
  mkdir -p "$out_dir"

  {
    printf '-----BEGIN %s-----\n' "$label"
    printf '%s' "$payload" | fold -w 64
    printf '-----END %s-----\n' "$label"
  } >"$output"

  if [[ "$quiet" != "true" ]]; then
    ui_success "Normalized PEM written to: $output"
  fi
}

maybe_normalize_pem() {
  local input="$1"
  local type="${2:-auto}"
  local normalize="${3:-false}"

  if [[ "$normalize" != "true" ]]; then
    printf '%s\n' "$input"
    return 0
  fi

  local tmp
  tmp=$(mktemp)
  register_temp_file "$tmp"
  if ! normalize_pem "$input" "$tmp" "$type" "true"; then
    return 1
  fi
  printf '%s\n' "$tmp"
}

validate_pem_certificate() {
  local file="$1"

  if ! grep -q "BEGIN CERTIFICATE" "$file" 2>/dev/null; then
    ui_error "File does not contain PEM certificate markers: $file"
    ui_info "Expected: -----BEGIN CERTIFICATE-----"
    return 1
  fi

  if ! pem_strict_check "$file" '^-----BEGIN CERTIFICATE-----$' '^-----END CERTIFICATE-----$'; then
    ui_error "Malformed PEM certificate: unexpected content or invalid base64: $file"
    return 1
  fi

  if ! openssl x509 -in "$file" -noout 2>/dev/null; then
    ui_error "File is not a valid X.509 certificate: $file"
    return 1
  fi

  return 0
}

validate_pem_key() {
  local file="$1"

  if ! grep -qE '^-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----$' "$file" 2>/dev/null; then
    ui_error "File does not contain PEM private key markers: $file"
    ui_info "Expected: -----BEGIN PRIVATE KEY----- (or RSA/EC variant)"
    return 1
  fi

  local begin_line label
  begin_line=$(grep -m1 -E '^-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----$' "$file" 2>/dev/null || true)
  label="${begin_line#-----BEGIN }"
  label="${label%-----}"

  if ! pem_strict_check "$file" "^-----BEGIN ${label}-----$" "^-----END ${label}-----$"; then
    ui_error "Malformed PEM private key: unexpected content or invalid base64: $file"
    return 1
  fi

  return 0
}

validate_pfx() {
  local file="$1"
  local password="${2:-}"

  local pass_args=(-passin "pass:${password}")

  if ! openssl pkcs12 -in "$file" -noout "${pass_args[@]}" 2>/dev/null; then
    ui_error "Invalid PFX/P12 file or incorrect password: $file"
    return 1
  fi

  return 0
}

is_der_encoded() {
  local file="$1"

  # DER files start with 0x30 (SEQUENCE tag)
  local first_byte
  first_byte=$(od -A n -t x1 -N 1 "$file" 2>/dev/null | tr -d ' \n')

  [[ "$first_byte" == "30" ]]
}

validate_chain() {
  local cert="$1"
  local ca_bundle="$2"

  if openssl verify -CAfile "$ca_bundle" "$cert" 2>/dev/null | grep -q ": OK"; then
    ui_success "Certificate chain verified"
    return 0
  else
    ui_error "Certificate chain verification failed"
    ui_info "Certificate may not be signed by the provided CA"
    return 1
  fi
}

validate_key_matches_cert() {
  local cert="$1"
  local key="$2"

  local cert_mod key_mod
  cert_mod=$(openssl x509 -noout -modulus -in "$cert" 2>/dev/null | openssl md5)
  key_mod=$(openssl rsa -noout -modulus -in "$key" 2>/dev/null | openssl md5)

  if [[ "$cert_mod" == "$key_mod" ]]; then
    ui_success "Private key matches certificate"
    return 0
  else
    ui_error "Private key does NOT match certificate"
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Certificate Information
# ═══════════════════════════════════════════════════════════════════════════════

show_cert_info() {
  local file="$1"
  local password="${2:-}"

  local info
  info=$(get_cert_info "$file" "$password")
  if [[ -n "$info" ]]; then
    ui_box "$info"
  fi
}

get_cert_info() {
  local file="$1"
  local password="${2:-}"

  local info=""
  local ext="${file##*.}"
  ext=$(_lowercase "$ext")

  case "$ext" in
  pfx | p12)
    info=$(openssl pkcs12 -in "$file" -nokeys -passin "pass:$password" 2>/dev/null |
      openssl x509 -noout -subject -issuer -dates -serial 2>/dev/null)
    ;;
  der)
    info=$(openssl x509 -in "$file" -inform DER -noout -subject -issuer -dates -serial 2>/dev/null)
    ;;
  *)
    info=$(openssl x509 -in "$file" -noout -subject -issuer -dates -serial 2>/dev/null)
    ;;
  esac

  printf '%s\n' "$info"
}

show_cert_info_interactive() {
  local file="$1"
  local ext="${file##*.}"
  ext=$(_lowercase "$ext")

  local password=""
  local info
  info=$(get_cert_info "$file" "$password")

  if [[ -z "$info" && "$ext" =~ ^(pfx|p12)$ ]] && ui_is_interactive; then
    if ui_confirm "Is the PFX password protected?"; then
      password=$(ui_input "Password" "" "true") || return 1
      info=$(get_cert_info "$file" "$password")
    fi
  fi

  if [[ -n "$info" ]]; then
    ui_box "$info"
  else
    ui_warning "Could not read certificate info"
  fi
}

detect_file_type() {
  local file="$1"
  local ext="${file##*.}"
  ext=$(_lowercase "$ext")

  case "$ext" in
  pfx | p12) echo "pfx"; return 0 ;;
  der) echo "der"; return 0 ;;
  key) echo "key"; return 0 ;;
  base64 | b64) echo "base64"; return 0 ;;
  esac

  local has_cert="" has_key=""
  if grep -q "BEGIN CERTIFICATE" "$file" 2>/dev/null; then
    has_cert="yes"
  fi
  if grep -qE '^-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----$' "$file" 2>/dev/null; then
    has_key="yes"
  fi

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

check_expiration() {
  local file="$1"
  local days="${2:-30}"

  if openssl x509 -in "$file" -checkend $((days * 86400)) -noout 2>/dev/null; then
    ui_success "Certificate valid for at least $days more days"
    return 0
  else
    ui_warning "Certificate expires within $days days (or is already expired)"
    local expiry
    expiry=$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | cut -d= -f2)
    ui_info "Expiration: $expiry"
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Conversion Functions
# ═══════════════════════════════════════════════════════════════════════════════

convert_pem_to_pfx() {
  local cert="$1"
  local key="$2"
  local output="$3"
  local password="${4:-}"
  local ca_bundle="${5:-}"
  local normalize="${6:-false}"

  cert=$(maybe_normalize_pem "$cert" "cert" "$normalize") || return 1
  key=$(maybe_normalize_pem "$key" "key" "$normalize") || return 1
  if [[ -n "$ca_bundle" ]]; then
    ca_bundle=$(maybe_normalize_pem "$ca_bundle" "cert" "$normalize") || return 1
  fi

  ui_step "Validating certificate..."
  validate_file_exists "$cert" "Certificate" || return 1
  validate_pem_certificate "$cert" || return 1

  ui_step "Validating private key..."
  validate_file_exists "$key" "Private key" || return 1
  validate_pem_key "$key" || return 1

  ui_step "Checking key/cert match..."
  validate_key_matches_cert "$cert" "$key" || return 1

  local cmd_args=(-export -out "$output" -inkey "$key" -in "$cert")

  if [[ -n "$ca_bundle" ]]; then
    ui_step "Validating CA bundle..."
    validate_file_exists "$ca_bundle" "CA bundle" || return 1
    validate_chain "$cert" "$ca_bundle" || {
      ui_confirm "Chain validation failed. Continue anyway?" || return 1
    }
    cmd_args+=(-certfile "$ca_bundle")
  fi

  cmd_args+=(-passout "pass:${password}")

  ui_step "Creating PFX..."
  if openssl pkcs12 "${cmd_args[@]}" 2>/dev/null; then
    ui_success "Created: $output"
    show_cert_info "$output" "$password"
    return 0
  else
    ui_error "Failed to create PFX"
    return 1
  fi
}

convert_pfx_to_pem() {
  local input="$1"
  local output_dir="$2"
  local password="${3:-}"

  ui_step "Validating PFX..."
  validate_file_exists "$input" "PFX file" || return 1
  validate_pfx "$input" "$password" || return 1

  mkdir -p "$output_dir"

  local basename
  basename=$(basename "$input" | sed 's/\.[^.]*$//')

  local cert_out="$output_dir/${basename}.crt"
  local key_out="$output_dir/${basename}.key"
  local ca_out="$output_dir/${basename}-ca.crt"

  local pass_args=(-passin "pass:${password}")

  ui_step "Extracting certificate..."
  if openssl pkcs12 -in "$input" -clcerts -nokeys "${pass_args[@]}" -out "$cert_out" 2>/dev/null; then
    ui_success "Certificate: $cert_out"
  else
    ui_error "Failed to extract certificate"
    return 1
  fi

  ui_step "Extracting private key..."
  if openssl pkcs12 -in "$input" -nocerts -nodes "${pass_args[@]}" -out "$key_out" 2>/dev/null; then
    chmod 600 "$key_out"
    ui_success "Private key: $key_out (mode 600)"
  else
    ui_error "Failed to extract private key"
    return 1
  fi

  ui_step "Extracting CA certificates..."
  if openssl pkcs12 -in "$input" -cacerts -nokeys "${pass_args[@]}" -out "$ca_out" 2>/dev/null; then
    if [[ -s "$ca_out" ]] && grep -q "BEGIN CERTIFICATE" "$ca_out"; then
      ui_success "CA bundle: $ca_out"
    else
      rm -f "$ca_out"
      ui_info "No CA certificates found in PFX"
    fi
  fi

  show_cert_info "$cert_out"
  return 0
}

convert_der_to_pem() {
  local input="$1"
  local output="$2"
  local type="${3:-cert}"

  ui_step "Validating input..."
  validate_file_exists "$input" "DER file" || return 1

  if ! is_der_encoded "$input"; then
    ui_warning "File may not be DER encoded"
    ui_confirm "Continue anyway?" || return 1
  fi

  ui_step "Converting to PEM..."

  if [[ "$type" == "key" ]]; then
    if openssl rsa -in "$input" -inform DER -out "$output" -outform PEM 2>/dev/null; then
      chmod 600 "$output"
      ui_success "Created: $output"
      return 0
    fi
  else
    if openssl x509 -in "$input" -inform DER -out "$output" -outform PEM 2>/dev/null; then
      ui_success "Created: $output"
      show_cert_info "$output"
      return 0
    fi
  fi

  ui_error "Conversion failed"
  return 1
}

convert_pem_to_der() {
  local input="$1"
  local output="$2"
  local type="${3:-cert}"
  local normalize="${4:-false}"

  input=$(maybe_normalize_pem "$input" "$type" "$normalize") || return 1

  ui_step "Validating input..."
  validate_file_exists "$input" "PEM file" || return 1

  if [[ "$type" == "key" ]]; then
    validate_pem_key "$input" || return 1
    ui_step "Converting to DER..."
    if openssl rsa -in "$input" -inform PEM -out "$output" -outform DER 2>/dev/null; then
      ui_success "Created: $output"
      return 0
    fi
  else
    validate_pem_certificate "$input" || return 1
    ui_step "Converting to DER..."
    if openssl x509 -in "$input" -inform PEM -out "$output" -outform DER 2>/dev/null; then
      ui_success "Created: $output"
      return 0
    fi
  fi

  ui_error "Conversion failed"
  return 1
}

create_base64() {
  local input="$1"
  local output="$2"

  validate_file_exists "$input" "Input file" || return 1

  ui_step "Encoding to Base64..."
  if base64 <"$input" | tr -d '\n' >"$output"; then
    ui_success "Created: $output"
    return 0
  else
    ui_error "Encoding failed"
    return 1
  fi
}

convert_pem_to_pfx_base64() {
  local cert="$1"
  local key="$2"
  local pfx_out="$3"
  local b64_out="$4"
  local password="${5:-}"
  local ca_bundle="${6:-}"
  local normalize="${7:-false}"

  if [[ -z "$pfx_out" ]]; then
    pfx_out="certificate.pfx"
  fi
  if [[ -z "$b64_out" ]]; then
    b64_out="${pfx_out}.base64"
  fi

  if ! convert_pem_to_pfx "$cert" "$key" "$pfx_out" "$password" "$ca_bundle" "$normalize"; then
    return 1
  fi

  create_base64 "$pfx_out" "$b64_out"
}

decode_base64() {
  local input="$1"
  local output="$2"

  validate_file_exists "$input" "Input file" || return 1

  ui_step "Decoding Base64..."
  if base64 --decode <"$input" >"$output" 2>/dev/null; then
    ui_success "Created: $output"
    return 0
  elif base64 -d <"$input" >"$output" 2>/dev/null; then
    ui_success "Created: $output"
    return 0
  elif base64 -D <"$input" >"$output" 2>/dev/null; then
    ui_success "Created: $output"
    return 0
  else
    ui_error "Decoding failed"
    return 1
  fi
}

combine_pem() {
  local cert="$1"
  local key="$2"
  local output="$3"
  local ca_bundle="${4:-}"
  local normalize="${5:-false}"

  cert=$(maybe_normalize_pem "$cert" "cert" "$normalize") || return 1
  key=$(maybe_normalize_pem "$key" "key" "$normalize") || return 1
  if [[ -n "$ca_bundle" && -f "$ca_bundle" ]]; then
    ca_bundle=$(maybe_normalize_pem "$ca_bundle" "cert" "$normalize") || return 1
  fi

  ui_step "Validating files..."
  validate_file_exists "$cert" "Certificate" || return 1
  validate_file_exists "$key" "Private key" || return 1
  validate_pem_certificate "$cert" || return 1
  validate_pem_key "$key" || return 1
  validate_key_matches_cert "$cert" "$key" || return 1

  ui_step "Creating combined PEM..."
  {
    cat "$cert"
    echo ""
    cat "$key"
    if [[ -n "$ca_bundle" && -f "$ca_bundle" ]]; then
      echo ""
      cat "$ca_bundle"
    fi
  } >"$output"

  chmod 600 "$output"
  ui_success "Created: $output"
  return 0
}

generate_csr() {
  local key_out="$1"
  local csr_out="$2"
  local cn="$3"
  local san="$4"
  local org="$5"
  local org_unit="$6"
  local city="$7"
  local state="$8"
  local country="$9"
  local key_size="${10:-2048}"

  if [[ -z "$cn" || -z "$org" || -z "$city" || -z "$state" || -z "$country" ]]; then
    ui_error "CN, Organization, City, State, and Country are required"
    return 1
  fi

  case "$key_size" in
  2048 | 4096) ;;
  *) ui_error "Key size must be 2048 or 4096"; return 1 ;;
  esac

  local subj="/C=${country}/ST=${state}/L=${city}/O=${org}"
  if [[ -n "$org_unit" ]]; then
    subj="${subj}/OU=${org_unit}"
  fi
  subj="${subj}/CN=${cn}"

  local csr_args=()
  if [[ -n "$san" ]]; then
    local san_list=""
    local IFS=','
    local entry
    for entry in $san; do
      entry=$(printf '%s' "$entry" | xargs)
      [[ -z "$entry" ]] && continue
      if [[ -z "$san_list" ]]; then
        san_list="DNS:${entry}"
      else
        san_list="${san_list},DNS:${entry}"
      fi
    done
    if [[ -n "$san_list" ]]; then
      csr_args+=(-addext "subjectAltName=${san_list}")
    fi
  fi

  ui_step "Generating private key..."
  if ! openssl genrsa -out "$key_out" "$key_size" >/dev/null 2>&1; then
    ui_error "Failed to generate private key"
    return 1
  fi
  chmod 600 "$key_out"
  ui_success "Key: $key_out (mode 600)"

  ui_step "Generating CSR..."
  if openssl req -new -key "$key_out" -out "$csr_out" -subj "$subj" "${csr_args[@]}" >/dev/null 2>&1; then
    ui_success "CSR: $csr_out"
    return 0
  else
    ui_error "Failed to generate CSR"
    return 1
  fi
}

generate_self_signed_cert() {
  local key_out="$1"
  local cert_out="$2"
  local cn="$3"
  local san="$4"
  local org="$5"
  local org_unit="$6"
  local city="$7"
  local state="$8"
  local country="$9"
  local key_size="${10:-2048}"
  local days="${11:-365}"
  local key_usage="${12:-digitalSignature}"
  local ext_key_usage="${13:-serverAuth}"

  if [[ -z "$cn" || -z "$org" || -z "$city" || -z "$state" || -z "$country" ]]; then
    ui_error "CN, Organization, City, State, and Country are required"
    return 1
  fi

  case "$key_size" in
  2048 | 4096) ;;
  *) ui_error "Key size must be 2048 or 4096"; return 1 ;;
  esac

  if ! [[ "$days" =~ ^[0-9]+$ ]]; then
    ui_error "Days must be a number"
    return 1
  fi

  local subj="/C=${country}/ST=${state}/L=${city}/O=${org}"
  if [[ -n "$org_unit" ]]; then
    subj="${subj}/OU=${org_unit}"
  fi
  subj="${subj}/CN=${cn}"

  local addexts=()
  if [[ -n "$san" ]]; then
    local san_list=""
    local IFS=','
    local entry
    for entry in $san; do
      entry=$(printf '%s' "$entry" | xargs)
      [[ -z "$entry" ]] && continue
      if [[ -z "$san_list" ]]; then
        san_list="DNS:${entry}"
      else
        san_list="${san_list},DNS:${entry}"
      fi
    done
    if [[ -n "$san_list" ]]; then
      addexts+=(-addext "subjectAltName=${san_list}")
    fi
  fi
  if [[ -n "$key_usage" ]]; then
    addexts+=(-addext "keyUsage=${key_usage}")
  fi
  if [[ -n "$ext_key_usage" ]]; then
    addexts+=(-addext "extendedKeyUsage=${ext_key_usage}")
  fi

  ui_step "Generating self-signed certificate..."
  if openssl req -x509 -nodes -days "$days" -newkey "rsa:${key_size}" \
    -keyout "$key_out" -out "$cert_out" -subj "$subj" "${addexts[@]}" >/dev/null 2>&1; then
    chmod 600 "$key_out"
    ui_success "Key: $key_out (mode 600)"
    ui_success "Certificate: $cert_out"
    return 0
  else
    ui_error "Failed to generate self-signed certificate"
    return 1
  fi
}

generate_mkcert() {
  local cert_out="$1"
  local key_out="$2"
  local domains="$3"

  if ! command -v mkcert >/dev/null 2>&1; then
    ui_error "mkcert is not installed"
    return 1
  fi

  if [[ -z "$domains" ]]; then
    ui_error "At least one domain is required"
    return 1
  fi

  local -a domain_args=()
  local IFS=','
  local entry
  for entry in $domains; do
    entry=$(printf '%s' "$entry" | xargs)
    [[ -z "$entry" ]] && continue
    domain_args+=("$entry")
  done

  if [[ ${#domain_args[@]} -eq 0 ]]; then
    ui_error "At least one domain is required"
    return 1
  fi

  ui_step "Generating certificate with mkcert..."
  if mkcert -cert-file "$cert_out" -key-file "$key_out" "${domain_args[@]}" >/dev/null 2>&1; then
    ui_success "Certificate: $cert_out"
    ui_success "Key: $key_out"
    return 0
  else
    ui_error "mkcert failed"
    return 1
  fi
}

certbot_status() {
  if ! command -v certbot &>/dev/null; then
    ui_error "certbot not installed"
    return 1
  fi

  local certbot_out
  if ! certbot_out=$(certbot certificates 2>/dev/null); then
    if [[ $EUID -ne 0 ]]; then
      ui_error "certbot requires elevated privileges. Try: sudo $SCRIPT_NAME certbot-status"
    else
      ui_error "certbot certificates failed"
    fi
    return 1
  fi

  if ! echo "$certbot_out" | grep -q "Certificate Name:"; then
    ui_warning "No certificates found"
    return 0
  fi

  ui_header "Certbot Certificates" "Expiry Analysis"
  ui_info "Server: $(hostname)"
  ui_info "Date: $(date)"
  echo ""

  echo "$certbot_out" | grep -E "(Certificate Name|Domains|Expiry Date|Certificate Path)" || true
  echo ""

  local cert_name cert_path expiry
  local -a expiring=()

  while IFS= read -r line; do
    if [[ $line =~ Certificate\ Name:\ (.+) ]]; then
      cert_name="${BASH_REMATCH[1]}"
      cert_name=$(printf '%s' "$cert_name" | xargs)
      cert_path="/etc/letsencrypt/live/${cert_name}/cert.pem"

      if [[ -f "$cert_path" ]]; then
        expiry=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
        if ! openssl x509 -in "$cert_path" -checkend $((30 * 86400)) -noout 2>/dev/null; then
          ui_error "${cert_name}: expires within 30 days (expires: $expiry)"
          expiring+=("$cert_name")
        elif ! openssl x509 -in "$cert_path" -checkend $((60 * 86400)) -noout 2>/dev/null; then
          ui_warning "${cert_name}: expires within 60 days (expires: $expiry)"
          expiring+=("$cert_name")
        else
          ui_success "${cert_name}: valid for > 60 days (expires: $expiry)"
        fi
      else
        ui_warning "${cert_name}: cert file missing: $cert_path"
      fi
    fi
  done <<<"$certbot_out"

  if [[ ${#expiring[@]} -gt 0 ]]; then
    echo ""
    ui_info "Expiring soon: ${expiring[*]}"
  fi
}

certbot_renew_domain() {
  local domain="$1"
  local force="${2:-false}"

  if ! command -v certbot &>/dev/null; then
    ui_error "certbot not installed"
    return 1
  fi

  if [[ -z "$domain" ]]; then
    ui_error "Domain required (--domain)"
    return 1
  fi

  if [[ $EUID -ne 0 ]]; then
    ui_error "certbot renew requires root. Try: sudo $SCRIPT_NAME certbot-renew --domain $domain"
    return 1
  fi

  local args=(certonly --manual --preferred-challenges dns --domain "$domain")
  args+=(--deploy-hook "systemctl reload nginx 2>/dev/null || systemctl reload apache2 2>/dev/null")
  if [[ "$force" == "true" ]]; then
    args+=(--force-renewal)
  fi

  ui_step "Running certbot for ${domain}..."
  ui_info "Dig check URL: https://toolbox.googleapps.com/apps/dig/#TXT/_acme-challenge.${domain}"
  ui_warning "You may need to add a DNS TXT record when prompted."
  if certbot "${args[@]}"; then
    ui_success "Certificate renewed: ${domain}"
    if [[ -f "/etc/letsencrypt/live/${domain}/cert.pem" ]]; then
      openssl x509 -in "/etc/letsencrypt/live/${domain}/cert.pem" -noout -enddate | sed 's/^/  /'
    fi
    return 0
  else
    ui_error "Renewal failed"
    return 1
  fi
}

certbot_renew_expiring() {
  if ! command -v certbot &>/dev/null; then
    ui_error "certbot not installed"
    return 1
  fi

  if [[ $EUID -ne 0 ]]; then
    ui_error "certbot renew requires root. Try: sudo $SCRIPT_NAME certbot-renew-expiring"
    return 1
  fi

  local certbot_out
  if ! certbot_out=$(certbot certificates 2>/dev/null); then
    ui_error "certbot certificates failed"
    return 1
  fi

  if ! echo "$certbot_out" | grep -q "Certificate Name:"; then
    ui_warning "No certificates found"
    return 0
  fi

  local cert_name cert_path expiry
  local -a expiring=()

  while IFS= read -r line; do
    if [[ $line =~ Certificate\ Name:\ (.+) ]]; then
      cert_name="${BASH_REMATCH[1]}"
      cert_name=$(printf '%s' "$cert_name" | xargs)
      cert_path="/etc/letsencrypt/live/${cert_name}/cert.pem"

      if [[ -f "$cert_path" ]]; then
        expiry=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
        if ! openssl x509 -in "$cert_path" -checkend $((60 * 86400)) -noout 2>/dev/null; then
          expiring+=("$cert_name")
        fi
      fi
    fi
  done <<<"$certbot_out"

  if [[ ${#expiring[@]} -eq 0 ]]; then
    ui_success "All certificates are valid for more than 60 days"
    return 0
  fi

  ui_warning "Certificates expiring soon:"
  local cert
  for cert in "${expiring[@]}"; do
    printf '  - %s\n' "$cert"
  done

  echo ""
  ui_warning "If using manual DNS validation, you must add TXT records when prompted."
  if ! ui_confirm "Renew these certificates now?"; then
    return 0
  fi

  for cert in "${expiring[@]}"; do
    echo ""
    ui_step "Renewing: $cert"
    if certbot certonly --cert-name "$cert" --manual --preferred-challenges dns --force-renewal; then
      ui_success "Successfully renewed $cert"
    else
      ui_error "Failed to renew $cert"
    fi
  done

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet nginx; then
      nginx -t && systemctl reload nginx
      ui_success "nginx reloaded"
    elif systemctl is-active --quiet apache2; then
      apache2ctl configtest && systemctl reload apache2
      ui_success "apache2 reloaded"
    fi
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Interactive Menu
# ═══════════════════════════════════════════════════════════════════════════════

interactive_menu() {
  while true; do
    ui_clear
    ui_header "🔐 CertConv v${VERSION}" "Certificate Conversion Tool"
    local choice
    choice=$(ui_choose "Start here" \
      "Select a file (recommended)" \
      "Other tasks (CSR, self-sign, mkcert, certbot)" \
      "Exit")

    case "$choice" in
    "Select a file (recommended)") menu_file_first ;;
    "Other tasks (CSR, self-sign, mkcert, certbot)") menu_other_tasks ;;
    "Exit")
      ui_dim "👋 Goodbye!"
      exit 0
      ;;
    esac

    if ! ui_confirm "Perform another operation?"; then
      ui_dim "👋 Goodbye!"
      exit 0
    fi
  done
}

menu_file_first() {
  while true; do
    local file
    file=$(ui_file_picker "Select certificate file (.cer/.pem/.der/.pfx)") || return
    [[ -z "$file" ]] && return

    ui_clear
    ui_header "🔐 CertConv v${VERSION}" "Certificate Conversion Tool"

    local file_type
    file_type=$(detect_file_type "$file")

    if [[ "$file_type" == "cert" || "$file_type" == "pfx" || "$file_type" == "der" || "$file_type" == "combined" ]]; then
      show_cert_info_interactive "$file"
    fi

    if ! menu_file_actions "$file" "$file_type"; then
      return
    fi
  done
}

menu_file_first_with_file() {
  local file="$1"
  if [[ -z "$file" ]]; then
    return 0
  fi
  if [[ ! -f "$file" ]]; then
    ui_error "File not found: $file"
    return 1
  fi

  ui_clear
  ui_header "🔐 CertConv v${VERSION}" "Certificate Conversion Tool"

  local file_type
  file_type=$(detect_file_type "$file")

  if [[ "$file_type" == "cert" || "$file_type" == "pfx" || "$file_type" == "der" || "$file_type" == "combined" ]]; then
    show_cert_info_interactive "$file"
  fi

  menu_file_actions "$file" "$file_type"
}

menu_other_tasks() {
  local -a items=()
  if command -v mkcert >/dev/null 2>&1; then
    items+=("Generate with mkcert (recommended)")
  fi
  items+=("Generate CSR" "Generate Self-Signed Cert" "Certbot Status" "Certbot Renew Expiring" "Certbot Renew Domain" "Back")

  local choice
  choice=$(ui_choose "Other tasks" "${items[@]}")

  case "$choice" in
  "Generate with mkcert (recommended)") menu_mkcert ;;
  "Generate CSR") menu_generate_csr ;;
  "Generate Self-Signed Cert") menu_selfsign ;;
  "Certbot Status") certbot_status ;;
  "Certbot Renew Expiring") certbot_renew_expiring ;;
  "Certbot Renew Domain")
    local domain
    domain=$(ui_input "Domain to renew (FQDN)" "" "false") || return
    local force="false"
    if ui_confirm "Force renewal?"; then
      force="true"
    fi
    certbot_renew_domain "$domain" "$force"
    ;;
  "Back") return 0 ;;
  esac
}

menu_file_actions() {
  local file="$1"
  local file_type="$2"

  while true; do
    local -a items=()
    case "$file_type" in
    cert | combined)
      items+=("Inspect certificate (full)")
      items+=("Check expiration")
      items+=("Verify chain")
      items+=("Check key/cert match")
      items+=("Convert to PFX/P12")
      items+=("Convert to PFX + Base64 (Key Vault)")
      items+=("Convert to DER")
      items+=("Combine with key")
      items+=("Normalize PEM")
      items+=("Create Base64")
      ;;
    pfx)
      items+=("Inspect certificate (full)")
      items+=("Extract to PEM")
      items+=("Create Base64")
      ;;
    der)
      items+=("Inspect certificate (full)")
      items+=("Convert to PEM")
      items+=("Check expiration")
      ;;
    key)
      items+=("Convert to DER")
      items+=("Combine with cert")
      items+=("Normalize PEM")
      items+=("Create Base64")
      ;;
    base64)
      items+=("Decode Base64")
      ;;
    *)
      items+=("Create Base64")
      ;;
    esac

    items+=("Choose another file" "Back")

    local choice
    choice=$(ui_choose "Choose an action" "${items[@]}")

    case "$choice" in
    "Inspect certificate (full)") inspect_file "$file" ;;
    "Check expiration") menu_expiration_with_cert "$file" ;;
    "Verify chain") menu_verify_with_cert "$file" ;;
    "Check key/cert match") menu_match_with_cert "$file" ;;
    "Convert to PFX/P12") menu_pem_to_pfx_with_cert "$file" ;;
    "Convert to PFX + Base64 (Key Vault)") menu_pem_to_pfx_base64_with_cert "$file" ;;
    "Convert to DER") menu_pem_to_der_with_input "$file" ;;
    "Convert to PEM") menu_der_to_pem_with_input "$file" ;;
    "Extract to PEM") menu_pfx_to_pem_with_input "$file" ;;
    "Combine with key") menu_combine_with_cert "$file" ;;
    "Combine with cert") menu_combine_with_key "$file" ;;
    "Normalize PEM") menu_normalize_with_input "$file" ;;
    "Create Base64") menu_base64_with_input "$file" ;;
    "Decode Base64") menu_base64_decode_with_input "$file" ;;
    "Choose another file") return 1 ;;
    "Back") return 0 ;;
    esac
  done
}

menu_verify_with_cert() {
  local cert="$1"
  local ca
  ca=$(ui_file_picker "Select CA bundle/root" "cert") || return
  [[ -z "$ca" ]] && return
  echo ""
  validate_chain "$cert" "$ca"
}

menu_match_with_cert() {
  local cert="$1"
  local key
  key=$(ui_file_picker "Select private key" "key") || return
  [[ -z "$key" ]] && return
  echo ""
  validate_key_matches_cert "$cert" "$key"
}

menu_expiration_with_cert() {
  local cert="$1"
  local days
  days=$(ui_input "Days to check" "30") || return
  [[ -z "$days" ]] && days=30
  echo ""
  check_expiration "$cert" "$days"
}

menu_pem_to_pfx_with_cert() {
  local cert="$1"
  local key
  key=$(ui_file_picker "Select private key" "key") || return
  [[ -z "$key" ]] && return

  local ca_bundle=""
  if ui_confirm "Include CA bundle/chain?"; then
    ca_bundle=$(ui_file_picker "Select CA bundle" "cert") || true
  fi

  local output
  output=$(ui_input "Output filename" "certificate.pfx") || return

  local password=""
  if ui_confirm "Set export password?"; then
    password=$(ui_input "Export password" "" "true") || return
    local confirm
    confirm=$(ui_input "Confirm password" "" "true") || return
    if [[ "$password" != "$confirm" ]]; then
      ui_error "Passwords do not match"
      return 1
    fi
  fi

  echo ""
  convert_pem_to_pfx "$cert" "$key" "$output" "$password" "$ca_bundle"
}

menu_pem_to_pfx_base64_with_cert() {
  local cert="$1"
  local key
  key=$(ui_file_picker "Select private key" "key") || return
  [[ -z "$key" ]] && return

  local ca_bundle=""
  if ui_confirm "Include CA bundle/chain?"; then
    ca_bundle=$(ui_file_picker "Select CA bundle" "cert") || true
  fi

  local output
  output=$(ui_input "Output PFX filename" "certificate.pfx") || return

  local b64_output
  b64_output=$(ui_input "Output Base64 filename" "${output}.base64") || return

  local password=""
  if ui_confirm "Set export password?"; then
    password=$(ui_input "Export password" "" "true") || return
    local confirm
    confirm=$(ui_input "Confirm password" "" "true") || return
    if [[ "$password" != "$confirm" ]]; then
      ui_error "Passwords do not match"
      return 1
    fi
  fi

  echo ""
  convert_pem_to_pfx_base64 "$cert" "$key" "$output" "$b64_output" "$password" "$ca_bundle"
}

menu_pem_to_der_with_input() {
  local input="$1"
  local type="cert"
  local detected
  detected=$(detect_file_type "$input")
  if [[ "$detected" == "key" ]]; then
    type="key"
  fi

  if [[ "$detected" == "unknown" ]]; then
    local choice
    choice=$(ui_choose "What type of PEM file?" "Certificate" "Private Key") || return
    if [[ "$choice" == "Private Key" ]]; then
      type="key"
    fi
  fi

  local output
  if [[ "$type" == "key" ]]; then
    output=$(ui_input "Output filename" "private.der") || return
  else
    output=$(ui_input "Output filename" "certificate.der") || return
  fi

  convert_pem_to_der "$input" "$output" "$type"
}

menu_der_to_pem_with_input() {
  local input="$1"
  local type="cert"
  local choice
  choice=$(ui_choose "What type of DER file?" "Certificate" "Private Key") || return
  if [[ "$choice" == "Private Key" ]]; then
    type="key"
  fi

  local output
  if [[ "$type" == "key" ]]; then
    output=$(ui_input "Output filename" "private.key") || return
  else
    output=$(ui_input "Output filename" "certificate.pem") || return
  fi

  convert_der_to_pem "$input" "$output" "$type"
}

menu_pfx_to_pem_with_input() {
  local input="$1"
  local password=""
  if ui_confirm "Is the PFX password protected?"; then
    password=$(ui_input "PFX password" "" "true") || return
  fi

  local output_dir
  output_dir=$(ui_input "Output directory" ".") || return
  [[ -z "$output_dir" ]] && output_dir="."

  echo ""
  convert_pfx_to_pem "$input" "$output_dir" "$password"
}

menu_combine_with_cert() {
  local cert="$1"
  local key
  key=$(ui_file_picker "Select private key" "key") || return
  [[ -z "$key" ]] && return

  local ca_bundle=""
  if ui_confirm "Include CA bundle?"; then
    ca_bundle=$(ui_file_picker "Select CA bundle" "cert") || true
  fi

  local output
  output=$(ui_input "Output filename" "combined.pem") || return

  combine_pem "$cert" "$key" "$output" "$ca_bundle"
}

menu_combine_with_key() {
  local key="$1"
  local cert
  cert=$(ui_file_picker "Select certificate" "cert") || return
  [[ -z "$cert" ]] && return

  local ca_bundle=""
  if ui_confirm "Include CA bundle?"; then
    ca_bundle=$(ui_file_picker "Select CA bundle" "cert") || true
  fi

  local output
  output=$(ui_input "Output filename" "combined.pem") || return

  combine_pem "$cert" "$key" "$output" "$ca_bundle"
}

menu_normalize_with_input() {
  local input="$1"
  local type="auto"
  local detected
  detected=$(detect_file_type "$input")
  case "$detected" in
  cert) type="cert" ;;
  key) type="key" ;;
  *) type="auto" ;;
  esac

  if [[ "$type" == "auto" ]]; then
    local choice
    choice=$(ui_choose "What type of PEM file?" "Certificate" "Private Key" "Auto-detect") || return
    case "$choice" in
    "Certificate") type="cert" ;;
    "Private Key") type="key" ;;
    *) type="auto" ;;
    esac
  fi

  local output
  output=$(ui_input "Output filename" "${input}.normalized.pem") || return

  normalize_pem "$input" "$output" "$type"
}

menu_base64_with_input() {
  local input="$1"
  local output
  output=$(ui_input "Output filename" "${input}.base64") || return
  create_base64 "$input" "$output"
}

menu_base64_decode_with_input() {
  local input="$1"
  local output
  output=$(ui_input "Output filename" "${input}.decoded") || return
  decode_base64 "$input" "$output"
}

menu_pem_to_pfx() {
  echo ""
  ui_info "Select certificate file (.pem, .crt, .cer)"
  local cert
  cert=$(ui_file_picker "Select certificate" "cert") || return
  [[ -z "$cert" ]] && return

  ui_info "Select private key file (.pem, .key)"
  local key
  key=$(ui_file_picker "Select private key" "key") || return
  [[ -z "$key" ]] && return

  local ca_bundle=""
  if ui_confirm "Include CA bundle/chain?"; then
    ca_bundle=$(ui_file_picker "Select CA bundle" "cert") || true
  fi

  local output
  output=$(ui_input "Output filename" "certificate.pfx") || return
  [[ -z "$output" ]] && return

  local password=""
  if ui_confirm "Set export password?"; then
    password=$(ui_input "Export password" "" "true") || return
    local confirm
    confirm=$(ui_input "Confirm password" "" "true") || return
    if [[ "$password" != "$confirm" ]]; then
      ui_error "Passwords do not match"
      return 1
    fi
  fi

  echo ""
  convert_pem_to_pfx "$cert" "$key" "$output" "$password" "$ca_bundle"
}

menu_pfx_to_pem() {
  echo ""
  ui_info "Select PFX/P12 file"
  local input
  input=$(ui_file_picker "Select PFX" "cert") || return
  [[ -z "$input" ]] && return

  local password=""
  if ui_confirm "Is the PFX password protected?"; then
    password=$(ui_input "PFX password" "" "true") || return
  fi

  local output_dir
  output_dir=$(ui_input "Output directory" ".") || return
  [[ -z "$output_dir" ]] && output_dir="."

  echo ""
  convert_pfx_to_pem "$input" "$output_dir" "$password"
}

menu_der_to_pem() {
  local type
  type=$(ui_choose "What type of DER file?" "Certificate" "Private Key") || return

  local input
  input=$(ui_file_picker "Select DER file" "cert") || return
  [[ -z "$input" ]] && return

  local output
  if [[ "$type" == "Certificate" ]]; then
    output=$(ui_input "Output filename" "certificate.pem") || return
    convert_der_to_pem "$input" "$output" "cert"
  else
    output=$(ui_input "Output filename" "private.key") || return
    convert_der_to_pem "$input" "$output" "key"
  fi
}

menu_pem_to_der() {
  local type
  type=$(ui_choose "What type of PEM file?" "Certificate" "Private Key") || return

  local input
  input=$(ui_file_picker "Select PEM file" "cert") || return
  [[ -z "$input" ]] && return

  local output
  if [[ "$type" == "Certificate" ]]; then
    output=$(ui_input "Output filename" "certificate.der") || return
    convert_pem_to_der "$input" "$output" "cert"
  else
    output=$(ui_input "Output filename" "private.der") || return
    convert_pem_to_der "$input" "$output" "key"
  fi
}

menu_base64() {
  local input
  input=$(ui_file_picker "Select file to encode" "any") || return
  [[ -z "$input" ]] && return

  local output
  output=$(ui_input "Output filename" "${input}.base64") || return

  create_base64 "$input" "$output"
}

menu_base64_decode() {
  local input
  input=$(ui_file_picker "Select Base64 file to decode" "base64") || return
  [[ -z "$input" ]] && return

  local output
  output=$(ui_input "Output filename" "${input}.decoded") || return

  decode_base64 "$input" "$output"
}

menu_pem_to_pfx_base64() {
  echo ""
  ui_info "Select certificate file (.pem, .crt, .cer)"
  local cert
  cert=$(ui_file_picker "Select certificate" "cert") || return
  [[ -z "$cert" ]] && return

  ui_info "Select private key file (.pem, .key)"
  local key
  key=$(ui_file_picker "Select private key" "key") || return
  [[ -z "$key" ]] && return

  local ca_bundle=""
  if ui_confirm "Include CA bundle/chain?"; then
    ca_bundle=$(ui_file_picker "Select CA bundle" "cert") || true
  fi

  local output
  output=$(ui_input "Output PFX filename" "certificate.pfx") || return
  [[ -z "$output" ]] && return

  local b64_output
  b64_output=$(ui_input "Output Base64 filename" "${output}.base64") || return
  [[ -z "$b64_output" ]] && return

  local password=""
  if ui_confirm "Set export password?"; then
    password=$(ui_input "Export password" "" "true") || return
    local confirm
    confirm=$(ui_input "Confirm password" "" "true") || return
    if [[ "$password" != "$confirm" ]]; then
      ui_error "Passwords do not match"
      return 1
    fi
  fi

  echo ""
  convert_pem_to_pfx_base64 "$cert" "$key" "$output" "$b64_output" "$password" "$ca_bundle"
}

menu_normalize_pem() {
  local type
  type=$(ui_choose "What type of PEM file?" "Certificate" "Private Key" "Auto-detect") || return

  local input
  input=$(ui_file_picker "Select PEM file to normalize" "cert") || return
  [[ -z "$input" ]] && return

  local output
  output=$(ui_input "Output filename" "${input}.normalized.pem") || return

  case "$type" in
  "Certificate") normalize_pem "$input" "$output" "cert" ;;
  "Private Key") normalize_pem "$input" "$output" "key" ;;
  *) normalize_pem "$input" "$output" "auto" ;;
  esac
}

menu_generate_csr() {
  ui_info "Generate a CSR (Certificate Signing Request)"

  local cert_type
  cert_type=$(ui_choose "Certificate type" "SSL (default)") || return
  [[ -z "$cert_type" ]] && return

  local cn san org org_unit city state country key_size key_out csr_out
  cn=$(ui_input "Common Name (FQDN)" "" "false") || return
  [[ -z "$cn" ]] && {
    ui_error "Common Name is required"
    return 1
  }

  san=$(ui_input "Subject Alternative Names (comma-separated)" "" "false") || return
  org=$(ui_input "Organization (legal name)" "" "false") || return
  org_unit=$(ui_input "Department/OU (optional, deprecated)" "" "false") || return
  city=$(ui_input "City / Locality" "" "false") || return
  state=$(ui_input "State / Province" "" "false") || return
  country=$(ui_input "Country (2-letter code)" "" "false") || return
  key_size=$(ui_choose "Key size" "2048" "4096") || return

  key_out=$(ui_input "Output key filename" "private.key") || return
  csr_out=$(ui_input "Output CSR filename" "request.csr") || return

  echo ""
  generate_csr "$key_out" "$csr_out" "$cn" "$san" "$org" "$org_unit" "$city" "$state" "$country" "$key_size"
}

menu_selfsign() {
  ui_info "Generate a self-signed certificate"

  local cn san org org_unit city state country key_size days
  cn=$(ui_input "Common Name (FQDN)" "" "false") || return
  [[ -z "$cn" ]] && {
    ui_error "Common Name is required"
    return 1
  }

  san=$(ui_input "Subject Alternative Names (comma-separated)" "" "false") || return
  org=$(ui_input "Organization (legal name)" "" "false") || return
  org_unit=$(ui_input "Department/OU (optional, deprecated)" "" "false") || return
  city=$(ui_input "City / Locality" "" "false") || return
  state=$(ui_input "State / Province" "" "false") || return
  country=$(ui_input "Country (2-letter code)" "" "false") || return
  key_size=$(ui_choose "Key size" "2048" "4096") || return
  days=$(ui_input "Validity (days)" "365") || return

  local key_out csr_out
  key_out=$(ui_input "Output key filename" "private.key") || return
  csr_out=$(ui_input "Output certificate filename" "certificate.cer") || return

  echo ""
  generate_self_signed_cert "$key_out" "$csr_out" "$cn" "$san" "$org" "$org_unit" "$city" "$state" "$country" "$key_size" "$days"
}

menu_mkcert() {
  ui_info "Generate a local dev certificate with mkcert"

  if ! command -v mkcert >/dev/null 2>&1; then
    ui_error "mkcert is not installed"
    return 1
  fi

  local domains
  domains=$(ui_input "Domains (comma-separated)" "" "false") || return
  [[ -z "$domains" ]] && {
    ui_error "At least one domain is required"
    return 1
  }

  local cert_out key_out
  cert_out=$(ui_input "Output cert filename" "cert.pem") || return
  key_out=$(ui_input "Output key filename" "key.pem") || return

  echo ""
  generate_mkcert "$cert_out" "$key_out" "$domains"
}

menu_combine() {
  local cert
  cert=$(ui_file_picker "Select certificate" "cert") || return
  [[ -z "$cert" ]] && return

  local key
  key=$(ui_file_picker "Select private key" "key") || return
  [[ -z "$key" ]] && return

  local ca_bundle=""
  if ui_confirm "Include CA bundle?"; then
    ca_bundle=$(ui_file_picker "Select CA bundle" "cert") || true
  fi

  local output
  output=$(ui_input "Output filename" "combined.pem") || return

  combine_pem "$cert" "$key" "$output" "$ca_bundle"
}

menu_inspect() {
  local input
  input=$(ui_file_picker "Select certificate" "cert") || return
  [[ -z "$input" ]] && return
  inspect_file "$input"
}

inspect_file() {
  local input="$1"
  local ext="${input##*.}"
  ext=$(_lowercase "$ext")

  local password=""
  if [[ "$ext" =~ ^(pfx|p12)$ ]]; then
    if ui_confirm "Is the PFX password protected?"; then
      password=$(ui_input "Password" "" "true") || return
    fi
  fi

  echo ""
  local cert_text
  case "$ext" in
  pfx | p12)
    cert_text=$(openssl pkcs12 -in "$input" -nokeys -passin "pass:$password" 2>/dev/null |
      openssl x509 -text -noout 2>/dev/null)
    ;;
  der)
    cert_text=$(openssl x509 -in "$input" -inform DER -text -noout 2>/dev/null)
    ;;
  *)
    cert_text=$(openssl x509 -in "$input" -text -noout 2>/dev/null)
    ;;
  esac

  if [[ -n "$cert_text" ]]; then
    ui_pager "$cert_text"
  else
    ui_error "Could not read certificate"
  fi
}

menu_verify() {
  local cert
  cert=$(ui_file_picker "Select certificate to verify" "cert") || return
  [[ -z "$cert" ]] && return

  local ca
  ca=$(ui_file_picker "Select CA bundle/root" "cert") || return
  [[ -z "$ca" ]] && return

  echo ""
  validate_chain "$cert" "$ca"
}

menu_match() {
  local cert
  cert=$(ui_file_picker "Select certificate" "cert") || return
  [[ -z "$cert" ]] && return

  local key
  key=$(ui_file_picker "Select private key" "key") || return
  [[ -z "$key" ]] && return

  echo ""
  validate_key_matches_cert "$cert" "$key"
}

menu_expiration() {
  local input
  input=$(ui_file_picker "Select certificate" "cert") || return
  [[ -z "$input" ]] && return

  local days
  days=$(ui_input "Days to check" "30") || return
  [[ -z "$days" ]] && days=30

  echo ""
  check_expiration "$input" "$days"
}

# ═══════════════════════════════════════════════════════════════════════════════
# OpenSSL Version Check
# ═══════════════════════════════════════════════════════════════════════════════

check_openssl() {
  if ! command -v openssl &>/dev/null; then
    echo "Error: openssl is required but not found" >&2
    exit 1
  fi

  local version_output
  version_output=$(openssl version 2>/dev/null | tr -d '\r')
  ui_info "OpenSSL: $version_output"

  local version="" min_required=""
  if [[ "$version_output" =~ OpenSSL[[:space:]]+([0-9]+(\.[0-9]+){1,2}[a-zA-Z]?) ]]; then
    version="${BASH_REMATCH[1]}"
    min_required="$CERTCONV_MIN_OPENSSL_VERSION"
  elif [[ "$version_output" =~ LibreSSL[[:space:]]+([0-9]+(\.[0-9]+){1,2}) ]]; then
    version="${BASH_REMATCH[1]}"
    min_required="$CERTCONV_MIN_LIBRESSL_VERSION"
  else
    ui_warning "Unable to parse OpenSSL version; continuing without version check"
    return 0
  fi

  version="${version%%[!0-9.]*}"
  if ! version_ge "$version" "$min_required"; then
    ui_error "OpenSSL version too old: $version (minimum $min_required)"
    exit 1
  fi
}

check_prereqs() {
  check_openssl

  if ! dir_has_files "$CERTCONV_CERTS_DIR"; then
    ui_warning "Certs directory is missing or empty: $CERTCONV_CERTS_DIR"
    if ui_is_interactive; then
      if [[ -x "$SCRIPT_DIR/scripts/generate-local.sh" ]]; then
        if ui_confirm "Generate local sample certs now?"; then
          "$SCRIPT_DIR/scripts/generate-local.sh" "$CERTCONV_CERTS_DIR"
        fi
      else
        ui_info "Run: $SCRIPT_DIR/scripts/generate-local.sh $CERTCONV_CERTS_DIR"
      fi
    else
      ui_info "Run: $SCRIPT_DIR/scripts/generate-local.sh $CERTCONV_CERTS_DIR"
    fi
  fi

  local le_dir="${CERTCONV_CERTS_DIR%/}/letsencrypt"
  if ! dir_has_files "$le_dir"; then
    if ui_is_interactive; then
      if [[ -x "$SCRIPT_DIR/scripts/download-letsencrypt.sh" ]]; then
        if ui_confirm "Download Let’s Encrypt roots/intermediates now?"; then
          "$SCRIPT_DIR/scripts/download-letsencrypt.sh" "$le_dir"
        fi
      else
        ui_info "Run: $SCRIPT_DIR/scripts/download-letsencrypt.sh $le_dir"
      fi
    else
      ui_info "Run: $SCRIPT_DIR/scripts/download-letsencrypt.sh $le_dir"
    fi
  fi
}

version_ge() {
  local a="$1" b="$2"
  local -a a_parts b_parts
  IFS='.' read -r -a a_parts <<< "$a"
  IFS='.' read -r -a b_parts <<< "$b"

  local max i
  max=${#a_parts[@]}
  if [[ ${#b_parts[@]} -gt $max ]]; then
    max=${#b_parts[@]}
  fi

  for ((i = 0; i < max; i++)); do
    local ai="${a_parts[i]:-0}"
    local bi="${b_parts[i]:-0}"
    if ((ai > bi)); then
      return 0
    elif ((ai < bi)); then
      return 1
    fi
  done
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLI Interface
# ═══════════════════════════════════════════════════════════════════════════════

show_usage() {
  cat <<EOF
CertConv v${VERSION} - Certificate Conversion Tool

USAGE:
  $SCRIPT_NAME [command] [options]
  $SCRIPT_NAME                         # Interactive mode

COMMANDS:
  pem2pfx     Convert PEM cert + key to PFX/P12
  pem2pfxb64  Convert PEM cert + key to PFX and Base64
  pfx2pem     Extract PEM from PFX/P12
  der2pem     Convert DER to PEM
  pem2der     Convert PEM to DER
  base64      Create Base64 encoded file
  base64dec   Decode Base64 to a file
  combine     Combine cert + key into single PEM
  normalize   Normalize PEM (fix spacing)
  csr         Generate CSR + private key
  selfsign    Generate self-signed cert + key
  mkcert      Generate local dev cert via mkcert
  certbot-status      Show certbot certificates + expiry analysis
  certbot-renew       Renew a certbot certificate (manual DNS)
  certbot-renew-expiring  Renew certbot certs expiring soon
  inspect     Show certificate details
  verify      Verify certificate chain
  match       Check if key matches certificate
  expiry      Check certificate expiration

OPTIONS:
  -c, --cert      Certificate file
  -k, --key       Private key file
  -i, --input     Input file
  -f, --file      Start in file-first mode with a specific file
  -o, --output    Output file/directory
  --base64-output Output Base64 file (pem2pfxb64)
  -p, --password  PFX password
  -a, --ca        CA bundle file
  -d, --days      Days for expiry check (default: 30)
  --certs-dir     Default certs directory for input resolution
  --normalize     Normalize PEM input (fix spacing) before processing
  --type          Normalize type: cert|key|auto (normalize command)
  --cn            CSR Common Name (FQDN)
  --san           CSR SANs (comma-separated)
  --org           CSR Organization (legal name)
  --org-unit      CSR Department/OU (optional, deprecated)
  --city          CSR City/Locality
  --state         CSR State/Province
  --country       CSR Country (2-letter code)
  --key-size      CSR key size (2048 or 4096; default 2048)
  --valid-days    Self-sign validity (days; default 365)
  --key-usage     Self-sign keyUsage (default digitalSignature)
  --ext-key-usage Self-sign extendedKeyUsage (default serverAuth)
  --domains       mkcert domains (comma-separated)
  --domain        certbot domain (for certbot-renew)
  --force         certbot-renew forces renewal
  -y, --yes       Assume yes to prompts
  -n, --non-interactive  Disable interactive prompts
  -h, --help      Show this help

ENVIRONMENT:
  CERTCONV_NONINTERACTIVE=true  Disable interactive mode
  CERTCONV_ASSUME_YES=true      Auto-confirm prompts
  CERTCONV_FORCE_GUM=true       Force gum even if not TTY
  CERTCONV_CERTS_DIR=./certs    Default directory to resolve input files

EXAMPLES:
  # Interactive (recommended)
  $SCRIPT_NAME

  # Start in file-first mode
  $SCRIPT_NAME -f certs/example.pem

  # Normalize a PEM with odd spacing
  $SCRIPT_NAME normalize -i messy.pem -o cleaned.pem --type cert

  # Convert PEM to PFX with CA chain
  $SCRIPT_NAME pem2pfx -c server.crt -k server.key -a ca.crt -o server.pfx

  # Convert PEM to PFX and Base64 (Key Vault friendly)
  $SCRIPT_NAME pem2pfxb64 -c server.crt -k server.key -o server.pfx

  # Extract from PFX
  $SCRIPT_NAME pfx2pem -i server.pfx -o ./extracted -p mypassword

  # Generate a CSR
  $SCRIPT_NAME csr --cn www.example.com --san www.example.com,api.example.com \\
    --org "Example Inc" --city "San Francisco" --state "CA" --country "US" \\
    -o request.csr -k private.key

  # Self-sign a cert (similar to common app gateway workflows)
  $SCRIPT_NAME selfsign --cn app.example.com --san app.example.com \\
    --org "Example Inc" --city "San Francisco" --state "CA" --country "US" \\
    -o app.cer -k app.key

  # mkcert (local dev)
  $SCRIPT_NAME mkcert --domains app.local,api.app.local -o cert.pem -k key.pem

  # certbot status (requires sudo)
  sudo $SCRIPT_NAME certbot-status

  # Verify chain
  $SCRIPT_NAME verify -c server.crt -a ca-bundle.crt

  # Check expiration (90 days)
  $SCRIPT_NAME expiry -c server.crt -d 90
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

main() {
  # Early pass for flags that affect prereqs
  local -a early_args=("$@")
  local i
  local skip_prereqs="false"
  for ((i = 0; i < ${#early_args[@]}; i++)); do
    case "${early_args[i]}" in
    -h | --help) skip_prereqs="true" ;;
    -n | --non-interactive) CERTCONV_NONINTERACTIVE=true ;;
    -y | --yes) CERTCONV_ASSUME_YES=true ;;
    --certs-dir)
      if [[ -n "${early_args[i+1]:-}" ]]; then
        CERTCONV_CERTS_DIR="${early_args[i+1]}"
        ((i++))
      fi
      ;;
    esac
  done
  CERTCONV_CERTS_DIR=$(resolve_certs_dir "$CERTCONV_CERTS_DIR")

  # Check for openssl and version + prereqs
  if [[ "$skip_prereqs" != "true" ]]; then
    check_prereqs
  fi
  trap cleanup_temp_files EXIT

  # No args = interactive
  if [[ $# -eq 0 ]]; then
    interactive_menu
    exit 0
  fi

  # Parse arguments
  local command=""
  local cert_file="" key_file="" input_file="" output_file="" base64_output=""
  local selected_file=""
  local password="" ca_file="" days=30
  local normalize="false"
  local normalize_type="auto"
  local csr_cn="" csr_san="" csr_org="" csr_org_unit="" csr_city="" csr_state="" csr_country=""
  local csr_key_size="2048"
  local self_cn="" self_san="" self_org="" self_org_unit="" self_city="" self_state="" self_country=""
  local self_key_size="2048" self_days="365" self_key_usage="digitalSignature" self_ext_key_usage="serverAuth"
  local mkcert_domains=""
  local certbot_domain="" certbot_force="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
    -h | --help)
      show_usage
      exit 0
      ;;
    -y | --yes)
      CERTCONV_ASSUME_YES=true
      shift
      ;;
    -n | --non-interactive)
      CERTCONV_NONINTERACTIVE=true
      shift
      ;;
    --normalize)
      normalize="true"
      shift
      ;;
    --type)
      normalize_type="$2"
      shift 2
      ;;
    --cn)
      csr_cn="$2"
      self_cn="$2"
      shift 2
      ;;
    --san)
      csr_san="$2"
      self_san="$2"
      shift 2
      ;;
    --org)
      csr_org="$2"
      self_org="$2"
      shift 2
      ;;
    --org-unit)
      csr_org_unit="$2"
      self_org_unit="$2"
      shift 2
      ;;
    --city)
      csr_city="$2"
      self_city="$2"
      shift 2
      ;;
    --state)
      csr_state="$2"
      self_state="$2"
      shift 2
      ;;
    --country)
      csr_country="$2"
      self_country="$2"
      shift 2
      ;;
    --key-size)
      csr_key_size="$2"
      self_key_size="$2"
      shift 2
      ;;
    --valid-days)
      self_days="$2"
      shift 2
      ;;
    --key-usage)
      self_key_usage="$2"
      shift 2
      ;;
    --ext-key-usage)
      self_ext_key_usage="$2"
      shift 2
      ;;
    --domains)
      mkcert_domains="$2"
      shift 2
      ;;
    --domain)
      certbot_domain="$2"
      shift 2
      ;;
    --force)
      certbot_force="true"
      shift
      ;;
    -c | --cert)
      cert_file="$2"
      shift 2
      ;;
    -k | --key)
      key_file="$2"
      shift 2
      ;;
    -i | --input)
      input_file="$2"
      shift 2
      ;;
    -f | --file)
      selected_file="$2"
      shift 2
      ;;
    -o | --output)
      output_file="$2"
      shift 2
      ;;
    --base64-output)
      base64_output="$2"
      shift 2
      ;;
    -p | --password)
      password="$2"
      shift 2
      ;;
    -a | --ca)
      ca_file="$2"
      shift 2
      ;;
    -d | --days)
      days="$2"
      shift 2
      ;;
    --certs-dir)
      CERTCONV_CERTS_DIR="$2"
      shift 2
      ;;
    pem2pfx | pem2pfxb64 | pfx2pem | der2pem | pem2der | base64 | base64dec | combine | normalize | csr | selfsign | mkcert | certbot-status | certbot-renew | certbot-renew-expiring | inspect | verify | match | expiry)
      command="$1"
      shift
      ;;
    *)
      ui_error "Unknown option: $1"
      show_usage
      exit 1
      ;;
    esac
  done

  # Execute command
  if [[ -n "$selected_file" ]]; then
    selected_file=$(resolve_input_path "$selected_file")
  fi
  if [[ -n "$cert_file" ]]; then
    cert_file=$(resolve_input_path "$cert_file")
  fi
  if [[ -n "$key_file" ]]; then
    key_file=$(resolve_input_path "$key_file")
  fi
  if [[ -n "$input_file" ]]; then
    input_file=$(resolve_input_path "$input_file")
  fi
  if [[ -n "$ca_file" ]]; then
    ca_file=$(resolve_input_path "$ca_file")
  fi

  case "$command" in
  pem2pfx)
    [[ -z "$cert_file" ]] && {
      ui_error "Certificate required (-c)"
      exit 1
    }
    [[ -z "$key_file" ]] && {
      ui_error "Key required (-k)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="certificate.pfx"
    convert_pem_to_pfx "$cert_file" "$key_file" "$output_file" "$password" "$ca_file" "$normalize"
    ;;
  pem2pfxb64)
    [[ -z "$cert_file" ]] && {
      ui_error "Certificate required (-c)"
      exit 1
    }
    [[ -z "$key_file" ]] && {
      ui_error "Key required (-k)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="certificate.pfx"
    convert_pem_to_pfx_base64 "$cert_file" "$key_file" "$output_file" "$base64_output" "$password" "$ca_file" "$normalize"
    ;;
  pfx2pem)
    [[ -z "$input_file" ]] && {
      ui_error "Input required (-i)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="."
    convert_pfx_to_pem "$input_file" "$output_file" "$password"
    ;;
  der2pem)
    [[ -z "$input_file" ]] && {
      ui_error "Input required (-i)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="certificate.pem"
    convert_der_to_pem "$input_file" "$output_file" "cert"
    ;;
  pem2der)
    [[ -z "$input_file" ]] && {
      ui_error "Input required (-i)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="certificate.der"
    convert_pem_to_der "$input_file" "$output_file" "cert" "$normalize"
    ;;
  base64)
    [[ -z "$input_file" ]] && {
      ui_error "Input required (-i)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="${input_file}.base64"
    create_base64 "$input_file" "$output_file"
    ;;
  base64dec)
    [[ -z "$input_file" ]] && {
      ui_error "Input required (-i)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="${input_file}.decoded"
    decode_base64 "$input_file" "$output_file"
    ;;
  combine)
    [[ -z "$cert_file" ]] && {
      ui_error "Certificate required (-c)"
      exit 1
    }
    [[ -z "$key_file" ]] && {
      ui_error "Key required (-k)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="combined.pem"
    combine_pem "$cert_file" "$key_file" "$output_file" "$ca_file" "$normalize"
    ;;
  normalize)
    [[ -z "$input_file" ]] && {
      ui_error "Input required (-i)"
      exit 1
    }
    [[ -z "$output_file" ]] && output_file="${input_file}.normalized.pem"
    normalize_pem "$input_file" "$output_file" "$normalize_type"
    ;;
  csr)
    [[ -z "$output_file" ]] && output_file="request.csr"
    [[ -z "$key_file" ]] && key_file="private.key"
    generate_csr "$key_file" "$output_file" "$csr_cn" "$csr_san" "$csr_org" \
      "$csr_org_unit" "$csr_city" "$csr_state" "$csr_country" "$csr_key_size"
    ;;
  selfsign)
    [[ -z "$output_file" ]] && output_file="certificate.cer"
    [[ -z "$key_file" ]] && key_file="private.key"
    generate_self_signed_cert "$key_file" "$output_file" "$self_cn" "$self_san" "$self_org" \
      "$self_org_unit" "$self_city" "$self_state" "$self_country" "$self_key_size" \
      "$self_days" "$self_key_usage" "$self_ext_key_usage"
    ;;
  mkcert)
    [[ -z "$output_file" ]] && output_file="cert.pem"
    [[ -z "$key_file" ]] && key_file="key.pem"
    generate_mkcert "$output_file" "$key_file" "$mkcert_domains"
    ;;
  certbot-status)
    certbot_status
    ;;
  certbot-renew)
    certbot_renew_domain "$certbot_domain" "$certbot_force"
    ;;
  certbot-renew-expiring)
    certbot_renew_expiring
    ;;
  inspect)
    local file="${cert_file:-$input_file}"
    [[ -z "$file" ]] && {
      ui_error "Certificate required (-c or -i)"
      exit 1
    }
    if [[ "$normalize" == "true" ]]; then
      file=$(maybe_normalize_pem "$file" "cert" "$normalize") || exit 1
    fi
    show_cert_info "$file" "$password"
    ;;
  verify)
    [[ -z "$cert_file" ]] && {
      ui_error "Certificate required (-c)"
      exit 1
    }
    [[ -z "$ca_file" ]] && {
      ui_error "CA bundle required (-a)"
      exit 1
    }
    if [[ "$normalize" == "true" ]]; then
      cert_file=$(maybe_normalize_pem "$cert_file" "cert" "$normalize") || exit 1
      ca_file=$(maybe_normalize_pem "$ca_file" "cert" "$normalize") || exit 1
    fi
    validate_chain "$cert_file" "$ca_file"
    ;;
  match)
    [[ -z "$cert_file" ]] && {
      ui_error "Certificate required (-c)"
      exit 1
    }
    [[ -z "$key_file" ]] && {
      ui_error "Key required (-k)"
      exit 1
    }
    if [[ "$normalize" == "true" ]]; then
      cert_file=$(maybe_normalize_pem "$cert_file" "cert" "$normalize") || exit 1
      key_file=$(maybe_normalize_pem "$key_file" "key" "$normalize") || exit 1
    fi
    validate_key_matches_cert "$cert_file" "$key_file"
    ;;
  expiry)
    [[ -z "$cert_file" ]] && {
      ui_error "Certificate required (-c)"
      exit 1
    }
    if [[ "$normalize" == "true" ]]; then
      cert_file=$(maybe_normalize_pem "$cert_file" "cert" "$normalize") || exit 1
    fi
    check_expiration "$cert_file" "$days"
    ;;
  "")
    if [[ -n "$selected_file" ]]; then
      menu_file_first_with_file "$selected_file"
    else
      interactive_menu
    fi
    ;;
  *)
    ui_error "Unknown command: $command"
    show_usage
    exit 1
    ;;
  esac
}

main "$@"
