#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Generate an Ed25519 issuer signing key for the `env` key backend.
 *
 * A jurisdiction with no HSM and no cloud KMS still has to sign credentials with a key that
 * survives restarts and that verifiers can pin, and `ISSUER_KEY_BACKEND=env` is that path.
 * The key material is a JWK in an environment variable, so somebody has to produce one; until
 * this script existed the only way was a one-liner against the jose library that nothing
 * documented, which meant pilots either ran the ephemeral dev key (refused in production, by
 * design) or gave up.
 *
 *   npm run keys:issuer
 *
 * Prints the PRIVATE JWK as the single line `.env` expects, then the public half. Treat the
 * private line as a secret from the moment it appears: put it in the deployment's secret
 * store, never in a file that is committed, and keep it -- rotating the issuer key means every
 * credential signed with the old one must be re-issued or the old public key published
 * alongside the new one. See docs/DEPLOY.md, "Production checklist", for when to move to a
 * backend where the key cannot be read out at all.
 */
const { generateKeyPair, exportJWK } = require('jose');

async function main() {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const priv = await exportJWK(privateKey);
  const pub = await exportJWK(publicKey);
  const kid = process.argv[2] || 'issuer-key-1';
  console.log('# Private key: put this line in the deployment secret store (never commit it).');
  console.log(`ISSUER_PRIVATE_JWK=${JSON.stringify({ ...priv, kid })}`);
  console.log(`ISSUER_KID=${kid}`);
  console.log('ISSUER_KEY_BACKEND=env');
  console.log('');
  console.log('# Public key, safe to share; what verifiers and the DID document carry.');
  console.log(JSON.stringify({ ...pub, kid }));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
