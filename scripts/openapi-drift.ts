// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * OpenAPI drift check: every HTTP route the NestJS controllers declare is documented in
 * docs/openapi.yaml, and every documented operation exists in a controller.
 *
 * The OpenAPI file is the contract partners integrate against and the source the SDK's
 * types are generated from. It was hand-maintained and fell to 43 of 80 routes without
 * anything noticing, which meant the relationship and credential lifecycle (the ORCS core)
 * was invisible to anyone integrating through it. This script makes the gap a build
 * failure.
 *
 * Routes are read statically from the `@Controller` and `@Get`/`@Post`/... decorators, so
 * no database or Nest bootstrap is needed. Paths mounted on the Express app outside Nest
 * (the OIDC provider under /oidc, see src/main.ts) cannot be enumerated this way; documented
 * paths under those prefixes are accepted without a controller match.
 *
 * Usage: npm run lint:openapi
 */
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

const ROOT = path.resolve(__dirname, '..', '..');
const SRC = path.join(ROOT, 'src');
const SPEC = path.join(ROOT, 'docs', 'openapi.yaml');

/** Prefixes served by middleware mounted in src/main.ts rather than by a controller. */
const MOUNTED_OUTSIDE_NEST = ['/oidc/'];

const HTTP_METHODS = ['Get', 'Post', 'Put', 'Patch', 'Delete', 'Head', 'Options', 'All'];

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.controller.ts')) out.push(full);
  }
  return out;
}

/** Nest path syntax (`:residentId`, `:countryCode.json`) to OpenAPI (`{residentId}`). */
function normalise(prefix: string, route: string): string {
  const joined = `/${prefix}/${route}`.replace(/\/+/g, '/').replace(/\/$/, '') || '/';
  return joined.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}

function routesFromControllers(): Map<string, string> {
  const routes = new Map<string, string>(); // "get /path" -> file:line
  const controllerRe = /@Controller\((?:\s*'([^']*)'\s*)?\)/;
  const methodRe = new RegExp(`@(${HTTP_METHODS.join('|')})\\((?:\\s*'([^']*)'\\s*)?\\)`);
  for (const file of walk(SRC)) {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    let prefix: string | undefined;
    lines.forEach((line, i) => {
      const c = controllerRe.exec(line);
      if (c) {
        prefix = c[1] ?? '';
        return;
      }
      const m = methodRe.exec(line);
      if (!m) return;
      if (prefix === undefined) {
        throw new Error(`${path.relative(ROOT, file)}:${i + 1}: route before any @Controller`);
      }
      const method = m[1].toLowerCase();
      const key = `${method} ${normalise(prefix, m[2] ?? '')}`;
      routes.set(key, `${path.relative(ROOT, file)}:${i + 1}`);
    });
  }
  return routes;
}

function operationsFromSpec(): Set<string> {
  const doc = yaml.load(fs.readFileSync(SPEC, 'utf8')) as {
    paths?: Record<string, Record<string, unknown>>;
  };
  const ops = new Set<string>();
  for (const [p, item] of Object.entries(doc.paths ?? {})) {
    for (const method of Object.keys(item)) {
      if (['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method)) {
        ops.add(`${method} ${p}`);
      }
    }
  }
  return ops;
}

function main(): number {
  const routes = routesFromControllers();
  const ops = operationsFromSpec();

  const undocumented = [...routes.keys()].filter((k) => {
    if (ops.has(k)) return false;
    // `@All` matches any method; it is documented if any method on the path is.
    if (k.startsWith('all ')) {
      const p = k.slice(4);
      return ![...ops].some((op) => op.endsWith(` ${p}`));
    }
    return true;
  });
  const phantom = [...ops].filter((op) => {
    if (routes.has(op)) return false;
    const p = op.slice(op.indexOf(' ') + 1);
    if (routes.has(`all ${p}`)) return false;
    return !MOUNTED_OUTSIDE_NEST.some((prefix) => p.startsWith(prefix));
  });

  console.log(`controller routes: ${routes.size}`);
  console.log(`documented operations: ${ops.size}`);

  if (undocumented.length) {
    console.log(`\nIn a controller but not in docs/openapi.yaml (${undocumented.length}):`);
    for (const k of undocumented.sort()) console.log(`  ${k.toUpperCase().split(' ')[0]} ${k.split(' ')[1]}  (${routes.get(k)})`);
  }
  if (phantom.length) {
    console.log(`\nIn docs/openapi.yaml but no controller serves it (${phantom.length}):`);
    for (const op of phantom.sort()) console.log(`  ${op.toUpperCase().split(' ')[0]} ${op.split(' ')[1]}`);
  }
  if (undocumented.length || phantom.length) {
    console.log('\nFAIL: docs/openapi.yaml and the controllers disagree.');
    return 1;
  }
  console.log('\nPASS: every controller route is documented and every documented operation is served.');
  return 0;
}

process.exit(main());
