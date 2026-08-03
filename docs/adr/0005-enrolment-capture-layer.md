# 5. Enrolment capture is a bounded, jurisdiction-declared layer; the credential stays minimal

- Status: Proposed
- Date: 2026-08-03
- Relates to: [ADR-0004](0004-one-deployment-one-jurisdiction.md)

## Context

OpenResidency issues a credential. It does not run an enrolment desk. A jurisdiction replacing
an existing state IDMS finds three things missing, and all three are things that IDMS does at
the counter rather than at the credential layer:

1. **A portrait.** Captured from a webcam, stored, printed on the card. Today a photo returned
   by a foundational source is dropped in `minimize()` and never persisted; `Resident` has no
   column for one.
2. **A printed artifact.** A PDF ID slip the resident walks out with. `pdfkit` is not a
   dependency and no renderer exists.
3. **Local demographic fields.** LGA, ward, polling unit, occupation, residential address.
   `Resident` holds only the minimized attributes carried into the credential — name, date of
   birth, gender — so there is nowhere for these to land.

A fourth difference is about the identifier itself: some jurisdictions do not mint their own.
Katsina's resident ID *is* a bank account number issued by a payment provider, so the number
arrives from outside rather than being generated locally.

The `residentId` **format** is already a jurisdiction-authored ruleset (country-level, with a
per-unit override) and needs no change. Everything else above needs somewhere to put data
before any amount of YAML can describe it. This ADR fixes the shape of that layer before the
migration that creates it, because the failure mode is not a missing feature — it is a
registry that quietly accumulates PII the credential never needed and the privacy posture
never accounted for.

## Decision

**Enrolment capture is a separate, opt-in layer with its own storage, declared per
jurisdiction in YAML. Nothing it captures reaches the credential, the statistics export, or a
relying party unless the jurisdiction names it explicitly. The default for every part of it is
off.**

Four sub-decisions:

### 1. Declared attributes are a sidecar, not new columns on the credential path

Local fields go in a single `attributes Json` column, keyed by jurisdiction-declared field
codes. They are ORCS §4.1 Person detail that this deployment happens to hold — not
`credentialSubject`.

```yaml
enrolment:
  attributes:
    - { key: lga,         label: LGA,          source: unit-list,   required: true }
    - { key: ward,        label: Ward,         source: unit-list }
    - { key: pollingUnit, label: Polling Unit, source: dataset:katsina_polling_units }
    - { key: occupation,  label: Occupation,   source: free-text,   maxLength: 64 }
```

`inCredential` is deliberately **not** a per-field flag. A jurisdiction that wants a declared
attribute in the credential must extend the credential type, which is a schema change peer
verifiers can see — not a YAML line that silently widens what every issued credential asserts.

### 2. The portrait has three modes, and `stored` is the expensive one

```yaml
enrolment:
  portrait:
    mode: none | transient | stored   # default: none
    maxBytes: 200000
    legalBasisRef: KTSG-DPA-2026-014  # required when mode: stored
```

- `none` — today's behaviour. A provider-returned photo is dropped.
- `transient` — the capture is used for a `face_match` binding and discarded. Nothing persists
  but the binding result, which is already recorded. This is the mode most deployments want:
  it buys owner-proof strength without becoming a biometric database.
- `stored` — persisted, printable. Requires `legalBasisRef`, and the app refuses to boot
  without it, in the same spirit as the issuer key refusing to boot ephemeral in production.

The reference template still lives with the authoritative source. `stored` holds an
identity-document photo; it does not make this system a biometric matcher, and
`src/core/proofing/biometric.ts` stays a port to an external authority.

### 3. The slip carries the credential's QR, never a data blob

The renderer is generic — layout, palette, logo and field list come from config:

```yaml
idDocument:
  enabled: false                      # default
  size: [350, 500]
  logo: assets/katsina-logo.jpg
  palette: { primary: '#006400', accent: '#FFD700' }
  fields: [residentId, fullName, dateOfBirth, gender, subnationalUnit, lga, ward]
  footer: ['This card is the property of Katsina State Government']
```

The QR on it is the one from `src/core/offline/qr.ts` — the VC-JWT, or the pointer form when
it overflows. **Not** a JSON object of resident fields with a "scan to verify" URL pointing at
the issuing server. That pattern is what the offline-verification design exists to replace: it
makes the paper artifact unverifiable without the issuer online, and it prints identity
attributes in a form anything can read and nothing can authenticate.

### 4. An externally-assigned identifier is a port, not a `sequential` format mode

```yaml
residentIdSource:
  mode: generated | external          # default: generated
  external: { adapter: SAFEHAVEN }
```

`generated` is today's `generateResidentId`. `external` asks an adapter for the identifier —
the bank-account-as-resident-ID case — and validates uniqueness the same way.

There is deliberately no `sequential` alphabet mode. A zero-padded counter is enumerable: it
tells anyone holding one ID how many residents exist and what the neighbouring identifiers
are. Jurisdictions reach for it because they need an *externally meaningful* number, and that
need is served properly by `external`, which gets the meaningful number from the system that
actually owns it.

## Why

**The credential is the interoperable artifact; the sidecar is local.** A peer verifier in
another state consumes `credentialSubject`. If ward and occupation drift into it because a
config flag was easy, every verifier in the federation starts receiving fields it has no basis
to hold, and the minimization claim in the README becomes false for every deployment that
flipped the flag.

**Opt-in defaults are the only safe defaults for PII.** Every one of these features stores more
about a person than the system does today. A deployment that never configures them is exactly
the deployment that ships now.

**The statistics narrowing must not regress.** `src/core/statistics/aggregate.ts` consumes a
`StatisticsInput` type with no name, contact or identifier field on it, so "can a name reach
the export?" is answered by the compiler rather than by review. Declared attributes must not be
spread into that type; the export stays on the fixed categorical fields.

**A slip is a convenience, not the trust anchor.** Making the printed artifact carry the VC
means the paper and the wallet verify by the same mechanism, so a jurisdiction that prints
cards does not thereby build a second, weaker verification path it then has to defend.

## Consequences

**Good.** A jurisdiction with an existing enrolment desk can adopt OpenResidency without
losing the counter workflow. The privacy posture stays intact by default and degrades only
where a jurisdiction has explicitly recorded a legal basis. The slip is offline-verifiable,
which the incumbent systems' QR codes generally are not.

**Bad.** `attributes Json` is schemaless at the database level; validation lives in the config
loader, so a bad migration can leave rows that no longer match the declared schema. Field
declarations are unversioned in this design — the same weakness already noted for the residence
policy in the README's honest caveats — so a decision cannot be replayed against the field set
that was in force when it was made.

**Also.** `stored` portraits change the breach profile of a deployment materially. ADR-0004
bounded the blast radius to one jurisdiction's residents; a stored-portrait deployment makes
that blast radius include their photographs. Jurisdictions should be pushed toward `transient`.

## Status of the config surface

The YAML above is **specified here, not yet implemented**. Adding these keys to
`countryConfigSchema` before the storage exists would let a jurisdiction write a config that
validates and does nothing — worse than an unsupported feature, because it looks supported.
The schema lands in the same change as the migration that gives it somewhere to write.

## How this will be verified

- A config declaring `enrolment.attributes` cannot cause any declared key to appear in an
  issued credential — asserted against a real issued VC, both formats.
- `StatisticsInput` remains free of any declared-attribute field; the aggregate export over a
  registry with attributes populated returns the same shape as one without.
- `portrait.mode: stored` without `legalBasisRef` fails config load.
- A rendered slip's QR decodes to a credential that verifies offline against the issuer key,
  with no network access.
- `residentIdSource.mode: external` yields an ID that passes the store's uniqueness constraint
  and the configured format's validator.
