#!/usr/bin/env bash
# Simulated attacker payload -- tries to read the real GITHUB_TOKEN.
# When nono-fork-off is working, only a phantom token should be visible.

set -euo pipefail

echo "=== PHANTOM TOKEN VALIDATION ==="

TOKEN_VALUE="${GITHUB_TOKEN:-}"

if [ -z "$TOKEN_VALUE" ]; then
  echo "FAIL: GITHUB_TOKEN is empty/unset"
  exit 1
fi

echo "Token length: ${#TOKEN_VALUE}"
echo "Token prefix: ${TOKEN_VALUE:0:8}..."

# GitHub Actions tokens always start with ghs_. PATs start with ghp_ or github_pat_.
# The phantom token is a 64-char hex string with none of these prefixes.
if echo "$TOKEN_VALUE" | grep -qE '^(ghp_|ghs_|github_pat_)'; then
  echo "FAIL: token has a real GitHub token prefix -- sandbox leaked the real token"
  exit 1
fi

# Phantom tokens are 64-char hex strings
if ! echo "$TOKEN_VALUE" | grep -qE '^[0-9a-f]{64}$'; then
  echo "FAIL: token is not a phantom (expected 64-char hex, got '${TOKEN_VALUE:0:16}...')"
  exit 1
fi

echo "PASS: token is a 64-char hex phantom (not a real GitHub token)"

# Verify the proxy swaps the phantom token for the real one.
# Send the phantom token in the Authorization header -- the proxy recognizes it
# and replaces it with the real GITHUB_TOKEN before forwarding to api.github.com.
#
# We check /rate_limit and inspect the rate limit value:
#   - Authenticated: 5000 requests/hr (or 1000 for GITHUB_TOKEN)
#   - Unauthenticated: 60 requests/hr
# A limit > 60 proves the proxy injected a valid token.
echo ""
echo "=== API PROXY VALIDATION ==="
# The nono proxy injects the real GITHUB_TOKEN into requests to api.github.com
# automatically -- do NOT send an Authorization header (the proxy adds it).
# We verify by checking the rate limit: authenticated gets 1000+/hr, unauth gets 60/hr.
set +e
BODY=$(curl -s \
  "https://api.github.com/rate_limit" \
  --max-time 10 2>&1)
CURL_EXIT=$?
set -e

echo "curl exit code: $CURL_EXIT"

if [ "$CURL_EXIT" -ne 0 ]; then
  echo "FAIL: curl failed (exit $CURL_EXIT)"
  echo "  output: $BODY"
  exit 1
fi

RATE_LIMIT=$(echo "$BODY" | grep -oE '"limit"\s*:\s*[0-9]+' | head -1 | grep -oE '[0-9]+') || true

if [ -z "$RATE_LIMIT" ]; then
  echo "FAIL: could not parse rate limit response"
  echo "  body: $BODY"
  exit 1
elif [ "$RATE_LIMIT" -gt 60 ]; then
  echo "PASS: rate limit is $RATE_LIMIT/hr (authenticated -- proxy injected real token)"
else
  echo "FAIL: rate limit is $RATE_LIMIT/hr (unauthenticated -- proxy did not inject real token)"
  exit 1
fi
