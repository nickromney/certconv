#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="${1:-certs/letsencrypt}"
PAGE_URL="https://letsencrypt.org/certificates/"

mkdir -p "$CERTS_DIR"

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
else
  echo "Error: curl or wget required" >&2
  exit 1
fi

page_tmp=$(mktemp)
trap 'rm -f "$page_tmp"' EXIT

if ! fetch "$PAGE_URL" "$page_tmp"; then
  echo "Error: failed to fetch $PAGE_URL" >&2
  exit 1
fi

# Extract .pem links from the page
links=$(grep -Eo 'href="[^"]+\.pem"' "$page_tmp" | cut -d'"' -f2 | sort -u)

# Fallback list if parsing fails
if [[ -z "$links" ]]; then
  links=$(cat <<'LIST'
https://letsencrypt.org/certs/isrgrootx1.pem
https://letsencrypt.org/certs/isrgrootx2.pem
https://letsencrypt.org/certs/lets-encrypt-r3.pem
https://letsencrypt.org/certs/lets-encrypt-e1.pem
https://letsencrypt.org/certs/lets-encrypt-r10.pem
https://letsencrypt.org/certs/lets-encrypt-e9.pem
https://letsencrypt.org/certs/lets-encrypt-r11.pem
https://letsencrypt.org/certs/lets-encrypt-e10.pem
https://letsencrypt.org/certs/lets-encrypt-r12.pem
https://letsencrypt.org/certs/lets-encrypt-e11.pem
https://letsencrypt.org/certs/lets-encrypt-r13.pem
https://letsencrypt.org/certs/lets-encrypt-e12.pem
LIST
)
fi

count=0
while IFS= read -r link; do
  [[ -z "$link" ]] && continue
  if [[ "$link" =~ ^https?:// ]]; then
    url="$link"
  elif [[ "$link" == /* ]]; then
    url="https://letsencrypt.org${link}"
  else
    url="https://letsencrypt.org/${link}"
  fi

  filename=$(basename "$url")
  fetch "$url" "$CERTS_DIR/$filename"
  count=$((count + 1))
  printf 'Fetched %s\n' "$filename"
done <<< "$links"

printf 'Downloaded %s certificate(s) to %s\n' "$count" "$CERTS_DIR"
