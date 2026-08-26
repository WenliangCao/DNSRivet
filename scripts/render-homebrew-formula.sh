#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 VERSION ARCHIVE_SHA256 OUTPUT.rb" >&2
    exit 2
fi

version=$1
sha256=$2
output=$3
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
template="$project_root/packaging/homebrew/dnsrivet.rb.in"

case "$version" in
    ''|*[!0-9.]*) echo "invalid version: $version" >&2; exit 2 ;;
esac
case "$sha256" in
    *[!0-9a-f]*|'') echo "invalid SHA-256: $sha256" >&2; exit 2 ;;
esac
if [ "${#sha256}" -ne 64 ]; then
    echo "invalid SHA-256 length" >&2
    exit 2
fi

/bin/mkdir -p "$(dirname -- "$output")"
/usr/bin/sed \
    -e "s/@VERSION@/$version/g" \
    -e "s/@SHA256@/$sha256/g" \
    "$template" > "$output"

echo "wrote Homebrew formula: $output"
