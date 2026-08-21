# Example jurisdiction configs

Configs here are **not loaded**. `COUNTRY_CONFIG_DIR` defaults to `config/countries`, and a
deployment copies what it needs from here into that directory.

They live apart for one reason: a config in the loaded directory is a config the application
boots with. `xo-oidc.yaml` declares an `upstreamOidc` profile whose client assertion key comes
from `XO_CLIENT_ASSERTION_KEY`, and building that client fails closed when the key is unset --
correctly, because an OIDC front door that silently does not work is worse than one that refuses
to start.

That combination is right for a deployment and wrong for a checkout. Shipped in
`config/countries`, it made `npm run start:dev` fail on a fresh clone: the platform reads the
upstream profile from whichever config declares one, found XO, and refused to start over a
secret nobody had set for an example jurisdiction that does not exist.

So: examples that need secrets live here. Copy one in, set its secrets, and the fail-closed
behaviour then protects you rather than blocking you.
