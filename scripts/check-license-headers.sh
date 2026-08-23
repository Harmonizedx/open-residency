#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Every source file carries an SPDX licence identifier.
#
# Apache-2.0 in a LICENSE file states the project's licence. It does not state the licence of a
# file somebody copies out of it, and copying is the point: this is a Digital Public Good, and
# an adopting government's counsel reads the file in front of them, not the repository root.
# SPDX headers are the machine-readable form of that answer (the REUSE Specification), and they
# are what an SBOM consumer and a licence scanner actually key on.
#
# This is a grep, not `reuse lint`. Full REUSE compliance covers every file in the tree --
# images, JSON, generated output -- and needs the `reuse` tool plus a REUSE.toml for files that
# cannot carry a comment. That is worth doing; it is a larger change than this, and a check
# nobody can run locally is a check that rots. This one runs anywhere bash and git exist.
set -euo pipefail

missing=0
while IFS= read -r file; do
  if ! grep -qF 'SPDX-License-Identifier' "$file"; then
    echo "  missing SPDX header: $file"
    missing=$((missing + 1))
  fi
done < <(git ls-files '*.ts' '*.js' '*.cjs' '*.mjs' '*.sh')

if [ "$missing" -gt 0 ]; then
  cat <<'EOF'

Add this as the first line (after any shebang):

  // SPDX-License-Identifier: Apache-2.0     <- .ts / .js / .cjs / .mjs
  # SPDX-License-Identifier: Apache-2.0      <- .sh

EOF
  echo "FAIL: $missing source file(s) without a licence header"
  exit 1
fi

echo "OK: every tracked source file carries an SPDX licence header"