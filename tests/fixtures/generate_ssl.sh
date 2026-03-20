#!/bin/bash
# Generate self-signed SSL cert for Sounding test targets.
# Run once — certs are committed to the repo (test-only, not real secrets).

DIR="$(cd "$(dirname "$0")" && pwd)/ssl"
mkdir -p "$DIR"

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$DIR/test.key" \
    -out "$DIR/test.crt" \
    -subj "/CN=ssl-target.test.local/O=Sounding Test/C=US"

echo "Generated $DIR/test.key and $DIR/test.crt"
