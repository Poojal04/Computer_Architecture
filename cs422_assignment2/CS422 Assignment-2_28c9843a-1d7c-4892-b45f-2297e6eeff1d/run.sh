#!/usr/bin/env bash
# run.sh — compile rsa_pin.cpp, run it on leaky_rsa, verify key
set -e

PIN="$HOME/Downloads/pin-external-4.0-99633-g5ca9893f2-gcc-linux"
TOOLS="$PIN/source/tools/ManualExamples"
BINARY="$HOME/Downloads/CS422 Assignment-2_28c9843a-1d7c-4892-b45f-2297e6eeff1d/leaky_rsa"

echo "=== CS422 A2: RSA Key Extractor ==="

echo "[1/3] Compiling rsa_pin.cpp..."
cd "$TOOLS"
rm -f obj-intel64/rsa_pin.so obj-intel64/rsa_pin.o
make obj-intel64/rsa_pin.so TARGET=intel64

echo "[2/3] Running PIN tool on leaky_rsa..."
"$PIN/pin" -t "$TOOLS/obj-intel64/rsa_pin.so" -- "$BINARY"

KEY=$(cat key.txt | tr -d '[:space:]')
echo "      Extracted key: $KEY"
echo "      key.txt written."

echo "[3/3] Verifying key..."
"$BINARY" -a "$KEY"
