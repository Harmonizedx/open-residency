// SPDX-License-Identifier: Apache-2.0
import { Controller, Get, Header } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { docsPage } from './docs-page';

/**
 * Serves the machine-readable API spec and a browsable docs page. The spec is the
 * source of truth the Interoperability SDK is generated against.
 *
 * ## Both routes are public on purpose (OR-04)
 *
 * The register's security review raised `/docs` and `/openapi.yaml` as unauthenticated.
 * They are, and they should be. This repository is public and `docs/openapi.yaml` is
 * tracked in it, so the spec is already published; gating the endpoint would hide nothing
 * and would break the SDK generation that reads it. A Digital Public Good publishing its
 * API surface is the point. What must not leak is the register's DATA, which these routes
 * do not touch.
 *
 * ## What WAS wrong here
 *
 * The page loaded Swagger UI from `cdn.jsdelivr.net` at a floating major (`@5`), with no
 * integrity check — third-party script executing on the register's own origin, changing
 * whenever the CDN published a release, with nothing to detect a substitution. For a
 * government residency register that is the more serious half of this finding and the
 * review did not raise it.
 *
 * Now pinned to an exact version with SRI, so a CDN serving different bytes is refused by
 * the browser instead of executed. The version is bumped deliberately, never floated: a
 * floating version and an integrity hash cannot both be right.
 */

@Controller()
export class MetaController {
  private specCache?: string;

  private spec(): string {
    if (!this.specCache) {
      const candidates = [
        join(process.cwd(), 'docs/openapi.yaml'),
        join(__dirname, '../../docs/openapi.yaml'),
      ];
      for (const p of candidates) {
        try {
          this.specCache = readFileSync(p, 'utf8');
          break;
        } catch {
          /* try next */
        }
      }
      this.specCache ??= 'openapi: 3.1.0\ninfo:\n  title: OpenResidency API\n  version: 0.1.0\npaths: {}\n';
    }
    return this.specCache;
  }

  @Get('openapi.yaml')
  @Header('content-type', 'application/yaml')
  openapi(): string {
    return this.spec();
  }

  @Get('docs')
  @Header('content-type', 'text/html')
  docs(): string {
    return docsPage();
  }
}
