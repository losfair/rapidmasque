#!/bin/sh
# Package a built binary as dist/rapidmasque-LABEL.tar.gz (+ .sha256).
# Usage: package.sh BINARY LABEL
set -eu
bin="$1"
label="$2"
name="rapidmasque-$label"
stage="$(mktemp -d)/$name"
mkdir -p "$stage" dist
cp "$bin" "$stage/rapidmasque"
chmod 755 "$stage/rapidmasque"
cp README.md LICENSE "$stage/"
tar -czf "dist/$name.tar.gz" -C "$(dirname "$stage")" "$name"
(cd dist && { sha256sum "$name.tar.gz" 2>/dev/null || shasum -a 256 "$name.tar.gz"; } > "$name.tar.gz.sha256")
cat "dist/$name.tar.gz.sha256"
