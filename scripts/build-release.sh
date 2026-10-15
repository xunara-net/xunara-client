#!/bin/sh
set -eu

version=${1:?usage: build-release.sh vVERSION EMPTY_OUTPUT_DIRECTORY}
output=${2:?usage: build-release.sh vVERSION EMPTY_OUTPUT_DIRECTORY}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
package_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -1)
[ "$version" = "v$package_version" ] || { echo 'Release version must match Cargo.toml' >&2; exit 1; }
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)
[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ] || { echo 'Output directory must be empty' >&2; exit 1; }
cd "$root"
command -v clang >/dev/null
host=$(rustc -vV | sed -n 's/^host: //p')
linker=$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld
[ -x "$linker" ] || { echo 'Rust LLD linker unavailable' >&2; exit 1; }
for architecture in x86_64 aarch64; do
    target=${architecture}-unknown-linux-musl
    rustup target add "$target"
    case "$architecture" in
        x86_64) asset=amd64; cc_variable=CC_x86_64_unknown_linux_musl; linker_variable=CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER;;
        aarch64) asset=arm64; cc_variable=CC_aarch64_unknown_linux_musl; linker_variable=CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER;;
    esac
    env "$cc_variable=clang" "$linker_variable=$linker" cargo build --locked --release --target "$target"
    cp "target/$target/release/xunara-client" "$output/xunara-client_linux_$asset"
done
cp config.example.json "$output/"
cp deploy/xunara-client.service "$output/"
cd "$output"
sha256sum xunara-client_linux_* config.example.json xunara-client.service > SHA256SUMS
printf 'Version: %s\nSource: %s\n' "$version" "$(git -C "$root" rev-parse HEAD)" > BUILD.txt
printf 'Static Linux releases: %s\n' "$output"
