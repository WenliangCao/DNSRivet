#!/bin/sh
set -eu

project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
dist_dir="$project_root/dist"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/dnsrivet-release.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM

toolchain_bin="${DNSRIVET_RUST_BIN:-$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin}"
cargo="${CARGO:-$toolchain_bin/cargo}"
if [ -n "${RUSTUP:-}" ]; then
    rustup=$RUSTUP
elif [ -x "$HOME/.cargo/bin/rustup" ]; then
    rustup="$HOME/.cargo/bin/rustup"
elif [ -x /opt/homebrew/opt/rustup/bin/rustup ]; then
    rustup=/opt/homebrew/opt/rustup/bin/rustup
else
    rustup=rustup
fi

if [ "$(uname -s)" != "Darwin" ]; then
    echo "release packages can only be built on macOS" >&2
    exit 1
fi
if [ ! -x "$cargo" ]; then
    echo "cargo not found: $cargo" >&2
    exit 1
fi
if [ ! -x "$rustup" ]; then
    echo "rustup not found: $rustup" >&2
    exit 1
fi

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$project_root/Cargo.toml" | head -1)
if [ -z "$version" ]; then
    echo "could not read the package version from Cargo.toml" >&2
    exit 1
fi

find_identity() {
    purpose=$1
    /usr/bin/security find-identity -v -p basic 2>/dev/null |
        sed -n "s/.*\"\($purpose:[^\"]*\)\".*/\1/p" |
        head -1
}

app_identity=${DNSRIVET_APP_IDENTITY:-$(find_identity "Developer ID Application")}
installer_identity=${DNSRIVET_INSTALLER_IDENTITY:-$(find_identity "Developer ID Installer")}
if [ -z "$app_identity" ]; then
    echo "Developer ID Application identity not found" >&2
    exit 1
fi
if [ -z "$installer_identity" ]; then
    echo "Developer ID Installer identity not found" >&2
    echo "Create that certificate in the Apple Developer portal, then rerun this script." >&2
    exit 1
fi

export PATH="$toolchain_bin:$HOME/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin"
"$rustup" target add aarch64-apple-darwin x86_64-apple-darwin

cd "$project_root"
"$cargo" test --all-targets --all-features --locked
"$cargo" build --release --locked --target aarch64-apple-darwin
"$cargo" build --release --locked --target x86_64-apple-darwin

universal="$work_dir/dnsrivet"
/usr/bin/lipo -create \
    "$project_root/target/aarch64-apple-darwin/release/dnsrivet" \
    "$project_root/target/x86_64-apple-darwin/release/dnsrivet" \
    -output "$universal"
/bin/chmod 0755 "$universal"
/usr/bin/codesign --force \
    --identifier io.github.wenliangcao.dnsrivet \
    --options runtime \
    --timestamp \
    --sign "$app_identity" \
    "$universal"
/usr/bin/codesign --verify --strict --verbose=2 "$universal"

archive_root="$work_dir/dnsrivet-v${version}-macos-universal2"
/bin/mkdir -p "$archive_root"
/bin/cp "$universal" "$archive_root/dnsrivet"
/bin/cp "$project_root/README.md" "$project_root/LICENSE" "$archive_root/"

/bin/mkdir -p "$dist_dir"
/usr/bin/find "$dist_dir" -mindepth 1 -maxdepth 1 -delete
archive="$dist_dir/dnsrivet-v${version}-macos-universal2.zip"
(
    cd "$work_dir"
    COPYFILE_DISABLE=1 /usr/bin/zip -qry "$archive" "$(basename "$archive_root")"
)

package_root="$work_dir/package-root"
/bin/mkdir -p "$package_root/Library/Application Support/DNSRivet"
/usr/bin/install -m 0755 "$universal" "$package_root/Library/Application Support/DNSRivet/dnsrivet"

package="$dist_dir/DNSRivet-v${version}.pkg"
/usr/bin/pkgbuild \
    --root "$package_root" \
    --scripts "$project_root/packaging/macos/scripts" \
    --identifier "io.github.wenliangcao.dnsrivet.pkg" \
    --version "$version" \
    --install-location / \
    --min-os-version 11.0 \
    --sign "$installer_identity" \
    "$package"

/usr/sbin/pkgutil --check-signature "$package"
(
    cd "$dist_dir"
    /usr/bin/shasum -a 256 "$(basename "$archive")" "$(basename "$package")" > SHA256SUMS
)

printf '\nRelease artifacts:\n'
/bin/ls -lh "$archive" "$package" "$dist_dir/SHA256SUMS"
printf '\nNext: DNSRIVET_NOTARY_PROFILE=<profile> scripts/notarize-release.sh %s %s\n' \
    "$package" "$archive"
