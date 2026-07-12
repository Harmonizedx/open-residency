import { Controller, Get, Header } from '@nestjs/common';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Serves the machine-readable API spec and a browsable docs page. The spec is the
 * source of truth the Interoperability SDK is generated against.
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
    return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenResidency API</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head><body>
<div id="swagger"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  window.onload = () => SwaggerUIBundle({ url: '/openapi.yaml', dom_id: '#swagger' });
</script>
</body></html>`;
  }
}
