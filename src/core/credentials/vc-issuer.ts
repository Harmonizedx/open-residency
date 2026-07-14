import { SignJWT } from 'jose';
import { IssuerKey } from './keystore';

/**
 * Issues the State Residency Verifiable Credential.
 *
 * Format: VC-JWT (a W3C Verifiable Credential carried inside a signed JWT). Chosen
 * over JSON-LD LD-Proofs because VC-JWT is compact (fits a QR code), needs no
 * canonicalization library, and verifies with a single Ed25519 check offline.
 */

export interface SubnationalUnitRef {
  country: string; // ISO 3166-1 alpha-2
  code: string; // e.g. KT
  name: string; // e.g. Katsina
  level: string; // state | province | lga | ward ...
}

export interface ResidencyClaims {
  /** Holder identifier: a did:key the holder controls, or a urn for custodial wallets. */
  holderId: string;
  residentId: string; // human-facing residency id, e.g. KT-7F3A-9K2P
  subnationalUnit: SubnationalUnitRef;
  foundational: {
    provider: string; // NG_NIN, IN_AADHAAR ...
    assuranceLevel: string;
    // NB: never the raw national id. A one-way subject reference only.
    subjectRef: string;
  };
  person: {
    fullName?: string;
    givenName?: string;
    familyName?: string;
    dateOfBirth?: string;
    gender?: string;
  };
  proofOfResidence: string; // attestation | document | selfDeclared
  provisional: boolean; // true if issued offline pending reconciliation
}

export interface IssueOptions {
  issuerDid: string;
  issuerName: string;
  type: string;
  context: string[];
  validityDays: number;
  /** Index assigned to this credential in the revocation status list. */
  statusListIndex: number;
  statusListUrl: string;
}

export interface IssuedCredential {
  jwt: string;
  credentialId: string;
  issuedAt: string;
  expiresAt: string;
  statusListIndex: number;
}

/**
 * Build the W3C Verifiable Credential body.
 *
 * Both issuance formats go through here -- the VC-JWT issuer below, and the Data
 * Integrity (`ldp_vc`) issuer used for wallet interoperability. Sharing one builder is
 * what guarantees the two formats assert exactly the same claims about a person. If
 * they were built separately they would drift, and a resident could end up holding two
 * credentials that disagree.
 */
export function buildCredentialBody(
  claims: ResidencyClaims,
  opts: IssueOptions,
  times: { credentialId: string; issuedAt: Date; expiresAt: Date },
): Record<string, unknown> {
  return {
    '@context': opts.context,
    id: times.credentialId,
    type: ['VerifiableCredential', opts.type],
    issuer: { id: opts.issuerDid, name: opts.issuerName },
    validFrom: times.issuedAt.toISOString(),
    validUntil: times.expiresAt.toISOString(),
    credentialStatus: {
      id: `${opts.statusListUrl}#${opts.statusListIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(opts.statusListIndex),
      statusListCredential: opts.statusListUrl,
    },
    credentialSubject: {
      id: claims.holderId,
      type: 'StateResident',
      residentId: claims.residentId,
      subnationalUnit: claims.subnationalUnit,
      foundationalAssurance: claims.foundational,
      person: claims.person,
      proofOfResidence: claims.proofOfResidence,
      provisional: claims.provisional,
    },
  };
}

export class VcIssuer {
  constructor(private key: IssuerKey) {}

  async issue(claims: ResidencyClaims, opts: IssueOptions): Promise<IssuedCredential> {
    const now = new Date();
    const exp = new Date(now.getTime() + opts.validityDays * 86400_000);
    const credentialId = `urn:uuid:${crypto.randomUUID()}`;

    const vc = buildCredentialBody(claims, opts, {
      credentialId,
      issuedAt: now,
      expiresAt: exp,
    });

    // VC-JWT registered-claim mirroring per the W3C VC-JWT profile.
    const jwt = await new SignJWT({ vc })
      .setProtectedHeader({ alg: 'EdDSA', kid: `${opts.issuerDid}#${this.key.kid}`, typ: 'JWT' })
      .setIssuer(opts.issuerDid)
      .setSubject(claims.holderId)
      .setJti(credentialId)
      .setIssuedAt(Math.floor(now.getTime() / 1000))
      .setExpirationTime(Math.floor(exp.getTime() / 1000))
      .sign(this.key.privateKey);

    return {
      jwt,
      credentialId,
      issuedAt: now.toISOString(),
      expiresAt: exp.toISOString(),
      statusListIndex: opts.statusListIndex,
    };
  }
}
