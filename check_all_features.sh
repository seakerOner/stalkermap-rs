#!/usr/bin/env bash
set -e

FEATURES=("std" "tokio-dep" "agnostic" "all")

CHOICE=$(printf "%s\n" "${FEATURES[@]}" | fzf --prompt="Select feature to test: ")

if [ -z "$CHOICE" ]; then
    echo "No feature selected, exiting."
    exit 1
fi

if [ "$CHOICE" = "all" ]; then
    RUN_FEATURES=("std" "tokio-dep" "agnostic")
else
    RUN_FEATURES=("$CHOICE")
fi

for FEATURE in "${RUN_FEATURES[@]}"; do
    echo "=============================="
    echo " Checking feature: $FEATURE"
    echo "=============================="
    
    # Clean previous builds to avoid feature mix
    cargo clean
    
    echo "-> Checking formatting"
    cargo fmt --all -- --check

    echo "-> Running Clippy"
    cargo clippy --no-default-features --features "$FEATURE" --all-targets -- -D warnings

    echo "-> Running tests"
    cargo test --no-default-features --features "$FEATURE"

    echo "-> Running doc tests"
    cargo test --doc --no-default-features --features "$FEATURE"

    if [ "$FEATURE" = "tokio-dep" ]; then
	echo "-> Running **tokio-dep** Rust Nightly Docs"
	rustup override set nightly
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --features tokio-dep --no-deps
	rustup override unset
    fi

    echo "------------------------------"
    echo "   Feature $FEATURE OK!"
    echo "------------------------------"
done

echo "All features passed successfully!"

