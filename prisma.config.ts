import { defineConfig } from 'prisma/config';

/**
 * Prisma CLI configuration.
 *
 * Prisma 7 removed `url` from the `datasource` block in schema.prisma. The connection string
 * now reaches the two consumers by separate routes:
 *
 *   - Migrate and Introspect (this file) read `datasource.url`.
 *   - The runtime client takes a driver adapter instead -- see src/prisma/prisma.service.ts.
 *
 * Both still resolve DATABASE_URL, so a deployment sets exactly one variable, as before. The
 * value is read here rather than hard-coded because this file is committed and the connection
 * string carries a password.
 */
/**
 * The datasource is attached only when DATABASE_URL is actually set.
 *
 * `prisma generate` connects to nothing -- it reads the schema and writes a client -- and the
 * image build runs it with no database in scope (see the build stage in the Dockerfile). The
 * `env()` helper resolves eagerly and throws on a missing variable, which would fail that
 * build for want of a value it never uses. Omitting the key instead leaves `generate` working
 * and lets the migrate commands, which genuinely need a connection, report the missing
 * datasource themselves.
 */
const databaseUrl = process.env.DATABASE_URL;

export default defineConfig({
  schema: 'prisma/schema.prisma',
  ...(databaseUrl ? { datasource: { url: databaseUrl } } : {}),
});