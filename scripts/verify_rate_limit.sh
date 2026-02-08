#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${BASE_URL:-"http://localhost:3001"}
EMAIL=${EMAIL:-"testuser@testuser.com"}
PASSWORD=${PASSWORD:-"WrongPassword123!"}

csrf_token=$(curl -s "${BASE_URL}/api/auth/csrf-token" | sed -n 's/.*"csrf_token":"\([^"]*\)".*/\1/p')

if [[ -z "${csrf_token}" ]]; then
  echo "Failed to get CSRF token"
  exit 1
fi
echo "Using CSRF token: ${csrf_token}"

for i in $(seq 1 7); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -H "X-CSRF-Token: ${csrf_token}" \
    -X POST "${BASE_URL}/api/auth/login" \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}")
  echo "Attempt ${i}: HTTP ${status}"
  sleep 0.2
 done

