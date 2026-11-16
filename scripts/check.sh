#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

SLOT="${CARGO_SLOT:-$(command -v cargo-slot || true)}"
[ -n "$SLOT" ] || SLOT="/home/concordium/.local/bin/cargo-slot"
[ -x "$SLOT" ] || SLOT=""

$SLOT cargo fmt --all -- --check
$SLOT cargo clippy --all-targets -- -D warnings
$SLOT cargo clippy --all-targets --all-features -- -D warnings
$SLOT cargo test
$SLOT cargo test --all-features
RUSTDOCFLAGS="-D warnings" $SLOT cargo doc --no-deps --all-features
! grep -rniE 'grorg|multimatrix|structmux|\bdm\b|action room' src Cargo.toml
