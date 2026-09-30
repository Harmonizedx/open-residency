#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate the SDK's typed contract (sdk/src/openapi.ts) from docs/openapi.yaml.
#
# openapi-typescript is run through npx at a pinned version rather than installed as a
# devDependency: it declares a peer on TypeScript 5 and this repository is on 6, and the
# generated file is plain TypeScript that compiles under either. The output is committed;
# CI regenerates it and fails on a diff, so a spec change cannot ship without the client.
set -euo pipefail
cd "$(dirname "$0")/.."

out=sdk/src/openapi.ts
tmp="$(mktemp)"
npx -y -p openapi-typescript@7.13.0 openapi-typescript docs/openapi.yaml -o "$tmp" >/dev/null
{
  echo '// SPDX-License-Identifier: Apache-2.0'
  cat "$tmp"
} > "$out"
rm -f "$tmp"
echo "wrote $out ($(wc -l < "$out" | tr -d ' ') lines)"
