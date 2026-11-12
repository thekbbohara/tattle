#!/bin/sh
# Build the static x86_64 Linux release tarball and SHA256SUMS into DIR.
# Local paths are remapped so the binary holds no user or folder names.
#   sh scripts/release.sh [DIR]      (default: target/dist)
set -eu
cd "$(dirname "$0")/.."
target=x86_64-unknown-linux-musl
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
name="tattle-v$version-x86_64-linux"
out=${1:-target/dist}
registry="${CARGO_HOME:-$HOME/.cargo}/registry/src"

rustup target add "$target" >/dev/null 2>&1 || true
RUSTFLAGS="--remap-path-prefix=$registry=/cargo --remap-path-prefix=$PWD=/tattle" \
  cargo build --release --locked --target "$target" -j "${JOBS:-4}"

bin="target/$target/release/tattle"
if strings "$bin" | grep -q "$HOME"; then
  echo "binary still contains $HOME" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$name"
cp "$bin" README.md LICENSE "$stage/$name/"
mkdir -p "$out"
# Reproducible archive: fixed owner, order and mtime (the last commit).
mtime=$(git log -1 --format=%cI)
tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner --mtime="$mtime" -cf - "$name" \
  | gzip -n9 > "$out/$name.tar.gz"
(cd "$out" && sha256sum "$name.tar.gz" > SHA256SUMS)
cat "$out/SHA256SUMS"
