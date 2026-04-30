#!/usr/bin/env bash
set -euo pipefail

if command -v npm >/dev/null 2>&1; then
  if [[ -f package-lock.json ]]; then
    npm ci
  else
    npm install
  fi
fi

for env_file in .env.local .env; do
  if [[ -f "../${env_file}" && ! -f "${env_file}" ]]; then
    cp "../${env_file}" "${env_file}"
  fi
done
