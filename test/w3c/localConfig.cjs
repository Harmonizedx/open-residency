/**
 * Implementation config for the official W3C test suites.
 *
 * The suites drive an implementation through the VC-API (`POST /credentials/issue`,
 * `POST /credentials/verify`, `POST /presentations/verify`), which this deployment
 * exposes. See README.md in this directory for how to run them.
 *
 * The VC-API endpoints are guarded by the admin key, because they will sign broadly what
 * they are handed and an open signing oracle under a government issuer's DID would let
 * anyone mint a credential that appears to come from the state. Set ADMIN_API_KEY to the
 * same value the server is running with.
 */
const BASE_URL = process.env.W3C_SUITE_BASE_URL || 'http://localhost:3000';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'dev-admin-key';

module.exports = {
  settings: {
    enableInteropTests: false,
    testAllImplementations: false,
  },
  implementations: [
    {
      name: 'OpenResidency',
      implementation: 'OpenResidency',
      issuers: [
        {
          id: 'did:web:id.katsina.gov.ng',
          endpoint: `${BASE_URL}/credentials/issue`,
          method: 'POST',
          headers: { Authorization: `Bearer ${ADMIN_API_KEY}` },
          tags: ['vc2.0', 'Ed25519Signature2020'],
        },
      ],
      verifiers: [
        {
          id: 'did:web:id.katsina.gov.ng',
          endpoint: `${BASE_URL}/credentials/verify`,
          method: 'POST',
          headers: { Authorization: `Bearer ${ADMIN_API_KEY}` },
          tags: ['vc2.0'],
        },
      ],
      vpVerifiers: [
        {
          id: 'did:web:id.katsina.gov.ng',
          endpoint: `${BASE_URL}/presentations/verify`,
          method: 'POST',
          headers: { Authorization: `Bearer ${ADMIN_API_KEY}` },
          tags: ['vc2.0'],
        },
      ],
    },
  ],
};
