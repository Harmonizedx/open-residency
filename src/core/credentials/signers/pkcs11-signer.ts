import { JWK } from 'jose';
import { Signer, SignatureAlg } from '../signer';

/**
 * PKCS#11 signer: the issuer key lives in an HSM and never enters this process.
 *
 * PKCS#11 rather than a cloud-specific SDK because it is the one interface every HSM
 * speaks -- Thales, Utimaco, YubiHSM, AWS CloudHSM, SoftHSM for development -- so a
 * deployment can change custody hardware without changing this code. It also keeps
 * Ed25519, which the credential format depends on end to end and which not every cloud
 * KMS offers.
 *
 * The security property this exists for: the private key is created inside the token
 * with CKA_EXTRACTABLE=false and CKA_SENSITIVE=true, so it cannot be read out even by
 * an attacker who fully controls this process. Compromising the application then buys
 * an attacker the ability to sign while they hold that access -- bad, but recoverable
 * by revoking the key. Compromising an application that holds the key material buys
 * them the ability to sign forever, including credentials backdated to before the
 * breach, and nothing short of re-issuing every credential ever signed recovers from it.
 *
 * `pkcs11js` is an optional dependency, required lazily: deployments that do not use an
 * HSM should not have to build a native module.
 */

/**
 * PKCS#11 v3.0 Edwards-curve constants.
 *
 * Defined here because pkcs11js 2.x does not export them: its constant table predates
 * the v3.0 mechanisms. The values are fixed by the specification.
 */
const CKK_EC_EDWARDS = 0x00000040;
const CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x00001055;
const CKM_EDDSA = 0x00001057;

/** DER encoding of the RFC 8410 Ed25519 OID (1.3.101.112), for CKA_EC_PARAMS. */
const ED25519_OID = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);
/** Some tokens want the legacy PrintableString "edwards25519" instead of the OID. */
const ED25519_PRINTABLE = Buffer.from([0x13, 0x0c, ...Buffer.from('edwards25519', 'ascii')]);

export const ED25519_EC_PARAMS = [ED25519_OID, ED25519_PRINTABLE];

export interface Pkcs11Config {
  /** Path to the vendor's PKCS#11 shared library. */
  libraryPath: string;
  /** User PIN. */
  pin: string;
  /** Select the slot by index into the slot list, or by token label. One is required. */
  slot?: number;
  tokenLabel?: string;
  /** CKA_LABEL of the key pair to sign with. */
  keyLabel: string;
  /** The `kid` this key is published under. Defaults to the key label. */
  kid?: string;
  /**
   * Public key, for tokens that do not keep a CKO_PUBLIC_KEY object alongside the
   * private one. When omitted, it is read from the token.
   */
  publicJwk?: JWK;
}

/** Strip the DER OCTET STRING wrapper some tokens put around CKA_EC_POINT. */
export function decodeEcPoint(raw: Buffer): Buffer {
  if (raw.length === 34 && raw[0] === 0x04 && raw[1] === 0x20) return raw.subarray(2);
  if (raw.length === 32) return raw;
  throw new Error(`unexpected CKA_EC_POINT length ${raw.length}; expected a 32-byte Ed25519 point`);
}

export class Pkcs11Signer implements Signer {
  readonly alg: SignatureAlg = 'EdDSA';

  /** Session and key handle are re-established on recovery, so neither is readonly. */
  private session: Buffer;
  private privateKeyHandle: Buffer;
  /** Tail of the serialised signing queue. See `serialise()`. */
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    readonly kid: string,
    readonly publicJwk: JWK,
    private readonly binding: Binding,
    private readonly cfg: Pkcs11Config,
    session: Buffer,
    privateKeyHandle: Buffer,
  ) {
    this.session = session;
    this.privateKeyHandle = privateKeyHandle;
  }

  /** Open the token, locate the signing key, and read its public half. */
  static async open(cfg: Pkcs11Config): Promise<Pkcs11Signer> {
    const pkcs11js = loadBinding();
    const p = new pkcs11js.PKCS11();
    p.load(cfg.libraryPath);
    p.C_Initialize();
    const binding: Binding = { pkcs11js, p };

    let opened: OpenedSession | undefined;
    try {
      opened = openSession(binding, cfg);
      const kid = cfg.kid ?? cfg.keyLabel;
      const publicJwk = cfg.publicJwk
        ? { ...cfg.publicJwk, kid }
        : readPublicJwk(binding, opened.session, cfg.keyLabel, kid);

      return new Pkcs11Signer(kid, publicJwk, binding, cfg, opened.session, opened.privateKeyHandle);
    } catch (e) {
      // Do not leave the token logged in and the library initialised on a failed open.
      try {
        if (opened) binding.p.C_CloseSession(opened.session);
      } catch {
        /* the session may already be gone; the original error is what matters */
      }
      try {
        binding.p.C_Finalize();
      } catch {
        /* ditto */
      }
      throw e;
    }
  }

  /**
   * Sign inside the token, recovering once from a dropped session.
   *
   * Two things are load-bearing here.
   *
   * SERIALISATION. C_SignInit and C_Sign are two calls against one session, and the
   * mechanism state set by the first belongs to the second. Two overlapping signers on the
   * same session interleave as init/init/sign/sign and each sign then runs under the other
   * caller's init -- which does not throw, it silently signs the wrong bytes. The calls are
   * synchronous today, so the pair happens to be atomic, but this is an async method and
   * `recover()` genuinely does suspend, so that property is not something to leave resting
   * on the absence of an `await`. Every signature goes through the queue.
   *
   * RECOVERY. A PKCS#11 session is not durable: HSMs time out idle sessions, network HSMs
   * reconnect, and appliances restart or fail over. Without this, one dropped session ends
   * issuance permanently -- every credential, token, request object, consent receipt and
   * operator session in the deployment signs through here -- and the only cure is a process
   * restart. Recovery is attempted once per signature; a second failure is real and raises.
   */
  async sign(data: Uint8Array): Promise<Uint8Array> {
    return this.serialise(async () => {
      try {
        return this.signOnce(data);
      } catch (e) {
        if (!isSessionError(e)) throw e;
        this.recover();
        return this.signOnce(data);
      }
    });
  }

  /**
   * The C_SignInit/C_Sign pair, with no suspension point between them.
   *
   * Deliberately synchronous: keeping it that way is what makes the pair indivisible even
   * if the queue above is ever changed.
   */
  private signOnce(data: Uint8Array): Uint8Array {
    const { p } = this.binding;
    const message = Buffer.from(data);
    p.C_SignInit(this.session, { mechanism: CKM_EDDSA }, this.privateKeyHandle);
    // Ed25519 signatures are always 64 bytes, which is the JWS form directly -- no DER
    // unwrapping, unlike ECDSA.
    const signature = p.C_Sign(this.session, message, Buffer.alloc(64));
    return new Uint8Array(signature);
  }

  /** Run `fn` after every previously queued signature, whether those succeeded or not. */
  private serialise<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    // The queue must not reject, or one failed signature would poison every later one.
    this.queue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * Re-establish the session, and refuse to continue if the key changed underneath us.
   *
   * The identity check is the point. A dropped session can mean the token was restarted --
   * but it can also mean it was re-provisioned, and silently signing with a key other than
   * the one already published in the DID document and JWKS would produce credentials that
   * verify for nobody, discovered only by the relying parties rejecting them. Failing shut
   * is the only safe answer.
   */
  private recover(): void {
    const { pkcs11js } = this.binding;
    try {
      this.binding.p.C_CloseSession(this.session);
    } catch {
      /* expected: the session we are recovering from is usually already invalid */
    }

    let opened: OpenedSession;
    try {
      opened = openSession(this.binding, this.cfg);
    } catch {
      // The library's own state can be stale too (CKR_CRYPTOKI_NOT_INITIALIZED after the
      // device went away), so fall back to a fresh binding rather than reusing this one.
      try {
        this.binding.p.C_Finalize();
      } catch {
        /* best effort */
      }
      const fresh = new pkcs11js.PKCS11();
      fresh.load(this.cfg.libraryPath);
      try {
        fresh.C_Initialize();
      } catch (e) {
        // C_Initialize is per-process per-library, so if a second signer in this process
        // still holds the library open, ours is already initialised and that is fine to
        // proceed on. Any other failure is real.
        if (!String((e as Error)?.message).includes('CKR_CRYPTOKI_ALREADY_INITIALIZED')) throw e;
      }
      this.binding.p = fresh;
      opened = openSession(this.binding, this.cfg);
    }

    // Only checkable on tokens that keep a public key object; when the public half was
    // supplied by config there is nothing on the token to compare against.
    try {
      const onToken = readPublicJwk(this.binding, opened.session, this.cfg.keyLabel, this.kid);
      if (onToken.x !== this.publicJwk.x) {
        try {
          this.binding.p.C_CloseSession(opened.session);
        } catch {
          /* best effort */
        }
        throw new Error(
          `the key labelled "${this.cfg.keyLabel}" changed while this signer was open: the ` +
            'token now holds a different public key than the one published for this issuer. ' +
            'Refusing to sign -- restart against the current key, or rotate deliberately.',
        );
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes('changed while this signer was open')) throw e;
      /* no public key object on this token: nothing to verify against */
    }

    this.session = opened.session;
    this.privateKeyHandle = opened.privateKeyHandle;
  }

  /**
   * Log out and release the token.
   *
   * Queued behind any signature still in flight: tearing the session down underneath a
   * C_SignInit/C_Sign pair would fail that signature for no reason at all.
   */
  async close(): Promise<void> {
    return this.serialise(async () => {
      const { p } = this.binding;
      try {
        p.C_Logout(this.session);
      } catch {
        /* already logged out, or the session is gone; C_Finalize below is what matters */
      }
      try {
        p.C_CloseSession(this.session);
      } catch {
        /* ditto -- releasing the library still has to happen */
      } finally {
        p.C_Finalize();
      }
    });
  }

  /**
   * Create a non-extractable Ed25519 key pair on the token.
   *
   * Intended for provisioning and for tests, not for the serving path -- a production
   * key is normally generated by the HSM operator under dual control, and this process
   * only ever gets a handle to it.
   */
  static async provision(cfg: Pkcs11Config): Promise<JWK> {
    const pkcs11js = loadBinding();
    const p = new pkcs11js.PKCS11();
    p.load(cfg.libraryPath);
    p.C_Initialize();

    let session: Buffer | undefined;
    try {
      const slot = selectSlot(pkcs11js, p, cfg);
      session = p.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
      p.C_Login(session, pkcs11js.CKU_USER, cfg.pin);

      let lastError: unknown;
      for (const ecParams of ED25519_EC_PARAMS) {
        try {
          p.C_GenerateKeyPair(
            session,
            { mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN },
            [
              { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
              { type: pkcs11js.CKA_KEY_TYPE, value: CKK_EC_EDWARDS },
              { type: pkcs11js.CKA_TOKEN, value: true },
              { type: pkcs11js.CKA_LABEL, value: cfg.keyLabel },
              { type: pkcs11js.CKA_EC_PARAMS, value: ecParams },
              { type: pkcs11js.CKA_VERIFY, value: true },
            ],
            [
              { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
              { type: pkcs11js.CKA_KEY_TYPE, value: CKK_EC_EDWARDS },
              { type: pkcs11js.CKA_TOKEN, value: true },
              { type: pkcs11js.CKA_LABEL, value: cfg.keyLabel },
              { type: pkcs11js.CKA_PRIVATE, value: true },
              { type: pkcs11js.CKA_SIGN, value: true },
              // The point of the exercise: the key must not be readable, by us or by
              // anyone who compromises us.
              { type: pkcs11js.CKA_EXTRACTABLE, value: false },
              { type: pkcs11js.CKA_SENSITIVE, value: true },
            ],
          );
          return readPublicJwk({ pkcs11js, p }, session!, cfg.keyLabel, cfg.kid ?? cfg.keyLabel);
        } catch (e) {
          // Tokens disagree on how Ed25519 is named in CKA_EC_PARAMS; try each encoding.
          lastError = e;
        }
      }
      throw new Error(
        `could not generate an Ed25519 key on this token: ${(lastError as Error)?.message}`,
      );
    } finally {
      try {
        if (session) {
          p.C_Logout(session);
          p.C_CloseSession(session);
        }
      } catch {
        /* best effort */
      }
      p.C_Finalize();
    }
  }
}

/**
 * The loaded library and the module handle. `p` is mutable because recovery may have to
 * discard a finalised module and load a fresh one.
 */
interface Binding {
  readonly pkcs11js: any;
  p: any;
}

interface OpenedSession {
  session: Buffer;
  privateKeyHandle: Buffer;
}

/** PKCS#11 return codes that mean "this session is gone", not "this request was bad". */
const SESSION_ERRORS = [
  'CKR_SESSION_HANDLE_INVALID',
  'CKR_SESSION_CLOSED',
  'CKR_USER_NOT_LOGGED_IN',
  'CKR_CRYPTOKI_NOT_INITIALIZED',
  'CKR_DEVICE_REMOVED',
  'CKR_DEVICE_ERROR',
  'CKR_TOKEN_NOT_PRESENT',
  'CKR_OPERATION_NOT_INITIALIZED',
];

/**
 * Distinguish a lost session from a genuine signing failure.
 *
 * Deliberately conservative: anything not on the list is treated as real and raised, so a
 * malformed request or a policy refusal is never retried into looking like a flake.
 */
export function isSessionError(e: unknown): boolean {
  const message = e instanceof Error ? e.message : String(e);
  const code = (e as { code?: unknown })?.code;
  const named = typeof code === 'string' ? code : '';
  return SESSION_ERRORS.some((c) => message.includes(c) || named === c);
}

/** Open a session, log in, and resolve the signing key handle. */
function openSession(binding: Binding, cfg: Pkcs11Config): OpenedSession {
  const { pkcs11js, p } = binding;
  const slot = selectSlot(pkcs11js, p, cfg);
  const session: Buffer = p.C_OpenSession(
    slot,
    pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION,
  );
  try {
    p.C_Login(session, pkcs11js.CKU_USER, cfg.pin);
    const privateKeyHandle = findObject(pkcs11js, p, session, pkcs11js.CKO_PRIVATE_KEY, cfg.keyLabel);
    if (!privateKeyHandle) {
      throw new Error(
        `no private key labelled "${cfg.keyLabel}" on this token. Provision one first ` +
          '(see Pkcs11Signer.provision).',
      );
    }
    return { session, privateKeyHandle };
  } catch (e) {
    try {
      p.C_CloseSession(session);
    } catch {
      /* the original error is what matters */
    }
    throw e;
  }
}

function loadBinding(): any {
  try {
    // Lazy and untyped: pkcs11js is an optional native dependency, so it must not be a
    // load-time import for deployments that never touch an HSM.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require('pkcs11js');
  } catch {
    throw new Error(
      'ISSUER_KEY_BACKEND=pkcs11 requires the optional `pkcs11js` dependency. ' +
        'Install it with `npm install pkcs11js`.',
    );
  }
}

function selectSlot(pkcs11js: any, p: any, cfg: Pkcs11Config): Buffer {
  const slots: Buffer[] = p.C_GetSlotList(true);
  if (slots.length === 0) throw new Error('the PKCS#11 library reports no slot with a token present');

  if (cfg.tokenLabel) {
    for (const slot of slots) {
      const info = p.C_GetTokenInfo(slot);
      if (String(info.label ?? '').trim() === cfg.tokenLabel) return slot;
    }
    throw new Error(`no token labelled "${cfg.tokenLabel}"`);
  }

  const index = cfg.slot ?? 0;
  if (index >= slots.length) {
    throw new Error(`slot index ${index} is out of range (${slots.length} slot(s) present)`);
  }
  return slots[index];
}

function findObject(
  pkcs11js: any,
  p: any,
  session: Buffer,
  objectClass: number,
  label: string,
): Buffer | null {
  p.C_FindObjectsInit(session, [
    { type: pkcs11js.CKA_CLASS, value: objectClass },
    { type: pkcs11js.CKA_LABEL, value: label },
  ]);
  try {
    return p.C_FindObjects(session) ?? null;
  } finally {
    p.C_FindObjectsFinal(session);
  }
}

function readPublicJwk(binding: Binding, session: Buffer, keyLabel: string, kid: string): JWK {
  const { pkcs11js, p } = binding;
  const handle = findObject(pkcs11js, p, session, pkcs11js.CKO_PUBLIC_KEY, keyLabel);
  if (!handle) {
    throw new Error(
      `no public key object labelled "${keyLabel}" on this token. Some HSMs do not store ` +
        'one; supply the public key explicitly via config instead.',
    );
  }
  const attrs = p.C_GetAttributeValue(session, handle, [{ type: pkcs11js.CKA_EC_POINT }]);
  const point = decodeEcPoint(Buffer.from(attrs[0].value));
  return { kty: 'OKP', crv: 'Ed25519', x: point.toString('base64url'), kid };
}