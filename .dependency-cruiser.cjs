/**
 * Architectural fence.
 *
 * The rules below are the ones this codebase already states in prose and has so far kept by
 * discipline. Discipline is not a control: it holds until the day someone in a hurry imports
 * the convenient thing, and nothing fails. Encoding them here means a violation stops a
 * build instead of being discovered later by whoever tries to reuse `src/core` somewhere
 * NestJS is not.
 *
 * Deliberately narrow. Every rule is one this repository can pass today, because a fence
 * that fails on arrival gets disabled rather than obeyed.
 */
module.exports = {
  forbidden: [
    {
      name: 'core-is-framework-agnostic',
      comment:
        "src/core is the portable half: it runs in a CI smoke test with no HTTP server and " +
        "must keep doing so. NestJS is the delivery mechanism, not the architecture. An " +
        "import of it here is how the domain quietly acquires a framework dependency and " +
        "stops being liftable into another runtime.",
      severity: 'error',
      from: { path: '^src/core' },
      to: { path: 'node_modules/@nestjs' },
    },
    {
      name: 'core-does-not-import-the-app',
      comment:
        'src/core must not reach back into the delivery layer (controllers, modules, the ' +
        'Prisma service). Dependencies point inward: the app composes the core, never the ' +
        'other way round. This is the rule that keeps the ports in src/core/**/ports.ts ' +
        'meaningful rather than decorative.',
      severity: 'error',
      from: { path: '^src/core' },
      to: {
        path: '^src/(?!core)',
      },
    },
    {
      name: 'core-does-not-import-prisma-client',
      comment:
        'The persistence PORT lives in core; the Prisma implementation lives outside it. ' +
        'Importing the generated client here would bind the domain to one database and undo ' +
        'the reason the port exists.',
      severity: 'error',
      from: { path: '^src/core' },
      to: { path: 'node_modules/(@prisma|\\.prisma)' },
    },
    {
      name: 'no-circular',
      comment:
        'A cycle means neither module can be understood, tested, or replaced on its own.',
      severity: 'error',
      from: {},
      to: { circular: true },
    },
    {
      name: 'no-orphans',
      comment:
        'A module nothing imports is either dead or a wiring bug -- the shape #13 turned out ' +
        'to have, where a fully-written client was reachable from nothing but its own test.',
      severity: 'warn',
      from: {
        orphan: true,
        pathNot: [
          '\\.d\\.ts$',
          '(^|/)\\.[^/]+\\.(js|cjs|mjs|ts)$',
          '^src/main\\.ts$',
        ],
      },
      to: {},
    },
  ],
  options: {
    doNotFollow: { path: 'node_modules' },
    tsConfig: { fileName: 'tsconfig.json' },
    tsPreCompilationDeps: true,
    exclude: { path: '(^|/)(dist|dist-core|node_modules)/' },
  },
};