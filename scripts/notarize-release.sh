#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: DNSRIVET_NOTARY_PROFILE=<profile> $0 PATH.pkg PATH.zip" >&2
    exit 2
fi
if [ -z "${DNSRIVET_NOTARY_PROFILE:-}" ]; then
    echo "DNSRIVET_NOTARY_PROFILE is required" >&2
    exit 2
fi

package=$1
archive=$2
for artifact in "$package" "$archive"; do
    if [ ! -f "$artifact" ]; then
        echo "artifact not found: $artifact" >&2
        exit 1
    fi
    /usr/bin/xcrun notarytool submit "$artifact" \
        --keychain-profile "$DNSRIVET_NOTARY_PROFILE" \
        --wait \
        --timeout 30m
done

# Installer tickets can be stapled. ZIP tickets are looked up online by
# Gatekeeper using the signed binary's code directory hash.
/usr/bin/xcrun stapler staple "$package"
/usr/bin/xcrun stapler validate "$package"
/usr/sbin/spctl --assess --type install --verbose=2 "$package"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/dnsrivet-notary-check.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
/usr/bin/unzip -q "$archive" -d "$work_dir"
binary=$(find "$work_dir" -type f -name dnsrivet -perm -111 -print -quit)
if [ -z "$binary" ]; then
    echo "notarized archive does not contain an executable named dnsrivet" >&2
    exit 1
fi
/usr/bin/codesign --verify --strict --verbose=2 "$binary"

# A bare command-line tool is not an app bundle, so `spctl --assess --type execute`
# reports "the code is valid but does not seem to be an app" even when the binary is
# correctly signed, notarized, and accepted by Gatekeeper. Tolerate exactly that
# outcome; every other rejection is a real failure. Letting the raw exit status abort
# the script here also skipped the checksum regeneration below, which silently left
# SHA256SUMS holding the pre-staple PKG digest.
assess_status=0
assess_output=$(/usr/sbin/spctl --assess --type execute --verbose=2 "$binary" 2>&1) \
    || assess_status=$?
printf '%s\n' "$assess_output"
if [ "$assess_status" -ne 0 ]; then
    case $assess_output in
        *"does not seem to be an app"*) ;;
        *)
            echo "Gatekeeper rejected the notarized binary" >&2
            exit 1
            ;;
    esac
fi

# Stapling changes the PKG bytes, so release checksums must be generated only
# after notarization is complete.
checksum_dir=$(dirname -- "$package")
if [ "$(dirname -- "$archive")" != "$checksum_dir" ]; then
    echo "PKG and ZIP must be in the same release directory" >&2
    exit 1
fi
(
    cd "$checksum_dir"
    /usr/bin/shasum -a 256 "$(basename -- "$archive")" "$(basename -- "$package")" > SHA256SUMS
)

echo "notarization and Gatekeeper validation passed"
