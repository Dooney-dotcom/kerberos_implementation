#!/bin/bash

# Check if secret was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <secret>"
  exit 1
fi

SECRET="$1"

# Generate 256-bit (32-byte) hex keys
K_V=$(openssl rand -hex 32)
K_TGS=$(openssl rand -hex 32)

# Derive SK by hashing the provided secret with SHA-256
SK=$(echo -n "$SECRET" | openssl dgst -sha256 | awk '{print $2}')

# Write environment variables to .env file
cat > .env <<EOF
K_V=$K_V
K_TGS=$K_TGS
SK=$SK
EOF

echo ".env file generated successfully:"
cat .env
