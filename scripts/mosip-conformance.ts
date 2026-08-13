/* eslint-disable no-console */
/**
 * MOSIP integration conformance.
 *
 * The authoritative statement of how far MOSIP integration has actually got. Documentation
 * about integration status goes stale within hours; this asserts each capability against the
 * real code paths and prints PASS, PARTIAL or FAIL, so a claim can be checked rather than
 * believed. When a document and this suite disagree, this suite is right.
 *
 * WHAT "PASS" MEANS HERE, PRECISELY. It means the capability is implemented and exercised
 * end to end against a counterparty built to MOSIP's published behaviour -- for the proof
 * suites, against credentials produced by the reference implementations rather than by this
 * codebase. It does NOT mean this has run against a live MOSIP deployment, and no verdict in
 * this file should ever be quoted as if it did. That distinction is restated in the summary
 * on every run, because it is the one a reader is most likely to drop.
 *
 * Unlike the ORCS suite, this one GATES: it exits non-zero on any non-PASS. It can afford to
 * because everything it measures is implemented, and a capability that regresses to PARTIAL
 * is a capability a deployment was relying on that has silently stopped working.
 */
import { execFileSync } from 'node:child_process';

type Verdict = 'PASS' | 'PARTIAL' | 'FAIL';

interface Result {
  criterion: string;
  verdict: Verdict;
  evidence: string;
  /** What is missing, when the verdict is not PASS. */
  gap?: string;
}

const results: Result[] = [];

function record(criterion: string, verdict: Verdict, evidence: string, gap?: string) {
  results.push({ criterion, verdict, evidence, gap });
}

/**
 * Run one smoke suite and report whether every assertion in it passed.
 *
 * Delegating rather than re-asserting is deliberate. Each suite already drives its
 * capability against a counterparty that behaves as MOSIP's published code and
 * configuration do; re-implementing thinner checks here would produce a second, weaker
 * definition of the same capability, and the two would drift. The suite is the evidence.
 */
function runSuite(script: string): { ok: boolean; assertions: number; detail: string } {
  try {
    const out = execFileSync('npm', ['run', '--silent', script], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const summary = /== (\d+) passed, (\d+) failed ==/.exec(out);
    if (!summary) return { ok: false, assertions: 0, detail: 'suite produced no summary line' };
    const passed = Number(summary[1]);
    const failed = Number(summary[2]);
    return {
      ok: failed === 0 && passed > 0,
      assertions: passed,
      detail: failed === 0 ? `${passed} assertions` : `${failed} of ${passed + failed} failed`,
    };
  } catch (e) {
    const err = e as { stdout?: string; message: string };
    const summary = /== (\d+) passed, (\d+) failed ==/.exec(err.stdout ?? '');
    return {
      ok: false,
      assertions: 0,
      detail: summary ? `${summary[2]} assertions failed` : err.message.split('\n')[0],
    };
  }
}

async function main() {
  console.log('\nMOSIP integration conformance\n');
  console.log('  Running the suites that constitute the evidence. This takes a moment.\n');

  // ---- 1. Issue credentials an Inji wallet can hold ------------------------
  const inji = runSuite('smoke:inji');
  record(
    'Credentials an Inji wallet can hold (OpenID4VCI, Draft 13 profile)',
    inji.ok ? 'PASS' : 'FAIL',
    `smoke:inji -- ${inji.detail}; ldp_vc with a DataIntegrityProof, RS256 holder proofs accepted, c_nonce echoed in the access token`,
    inji.ok ? undefined : 'the Inji profile suite does not pass',
  );

  // ---- 2. Verify credentials a MOSIP-era issuer signed ---------------------
  const suites = runSuite('smoke:ld-suites');
  record(
    'Verify credentials signed by a MOSIP/Inji Certify-era issuer',
    suites.ok ? 'PASS' : 'FAIL',
    `smoke:ld-suites -- ${suites.detail}; Ed25519Signature2020/2018 and RsaSignature2018 verified against credentials produced by the REFERENCE implementations, accepted per peer, verify-only`,
    suites.ok ? undefined : 'the inbound proof suites do not verify',
  );

  // ---- 3. Sign residents in at eSignet -------------------------------------
  const upstream = runSuite('smoke:upstream-oidc');
  record(
    'Sign residents in at an eSignet-shaped provider',
    upstream.ok ? 'PASS' : 'FAIL',
    `smoke:upstream-oidc -- ${upstream.detail}; private_key_jwt audienced at the token endpoint, PKCE, pinned provider keys, nested-JWT userinfo decrypted AND signature-verified, unmapped acr refused`,
    upstream.ok ? undefined : 'the upstream provider flow does not complete',
  );

  // ---- 4. Authenticate against MOSIP IDA -----------------------------------
  const ida = runSuite('smoke:mosip-ida');
  record(
    'Authenticate against MOSIP ID Authentication, and retrieve eKYC attributes',
    ida.ok ? 'PASS' : 'FAIL',
    `smoke:mosip-ida -- ${ida.detail}; the request envelope is opened by the test server (session key, request block, digest, thumbprint, detached JWS), and the eKYC response is decrypted AND its inner signature verified`,
    ida.ok ? undefined : 'the IDA envelope or the eKYC exchange does not round-trip',
  );

  // ---- 5. Nothing MOSIP-specific leaks into the core -----------------------
  //
  // The integration must not become a dependency. A deployment with no MOSIP anywhere near
  // it should be unable to tell this work happened, which is what keeps the four capabilities
  // above optional rather than architectural.
  // The word itself is not the problem: a comment explaining WHY an accommodation exists is
  // exactly what a reader needs, and the provider registry names MOSIP_IDA in the same table
  // that names NG_NIN and IN_AADHAAR -- that table is the mechanism by which providers are
  // optional, not a violation of it. What must not exist is CONTROL FLOW that behaves
  // differently because the counterparty is MOSIP, which is the thing that would turn an
  // option into a dependency.
  const grep = (pattern: string, extra = ''): string[] =>
    execFileSync('bash', ['-c', `grep -rnE ${JSON.stringify(pattern)} --include='*.ts' src/core ${extra} || true`], {
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean);

  // A conditional, comparison, or switch on a vendor identifier anywhere in the core.
  const vendorBranches = grep(
    "(===|!==|==|!=)\\s*['\\\"][^'\\\"]*(mosip|esignet|inji)|(includes|startsWith|match)\\s*\\(\\s*['\\\"][^'\\\"]*(mosip|esignet|inji)",
    // Comments are excluded here too. A doc comment that says "there is no
    // `if (wallet === 'inji')` here" describes the absence of the very thing being looked
    // for, and flagging it would make the check unable to coexist with its own explanation.
    '| grep -viE ":[0-9]+: *(\\*|//|/\\*)"',
  ).filter((line) => !line.includes('adapters/mosip-ida.adapter.ts'));

  // Any non-comment mention outside the IDA adapter and the registry's provider table.
  const nonComment = grep('(mosip|esignet|inji)', '| grep -viE ":[0-9]+: *(\\*|//|/\\*)"')
    .filter((line) => !line.startsWith('src/core/foundational/adapters/mosip-ida.adapter.ts'))
    .filter((line) => !/registry\.ts:\d+:\s*(import|MOSIP_IDA:)/.test(line));

  const clean = vendorBranches.length === 0 && nonComment.length === 0;
  record(
    'No MOSIP-specific behaviour in the core',
    clean ? 'PASS' : 'FAIL',
    clean
      ? 'no control flow anywhere in src/core branches on a MOSIP identifier; outside the IDA ' +
        'adapter and the provider registry table, MOSIP is named only in comments explaining ' +
        'why an accommodation exists -- so a deployment with no MOSIP cannot tell this work happened'
      : `vendor branching: ${vendorBranches.join(' ') || 'none'}; unexplained mentions: ${nonComment.join(' ') || 'none'}`,
    clean ? undefined : 'the integration has become a dependency rather than an option',
  );

  // ---- Report --------------------------------------------------------------
  const icon: Record<Verdict, string> = { PASS: '✓', PARTIAL: '~', FAIL: '✗' };
  console.log('');
  results.forEach((r, i) => {
    console.log(`  ${icon[r.verdict]} ${i + 1}. ${r.criterion} — ${r.verdict}`);
    console.log(`      ${r.evidence}`);
    if (r.gap) console.log(`      GAP: ${r.gap}`);
  });

  const passed = results.filter((r) => r.verdict === 'PASS').length;
  const partial = results.filter((r) => r.verdict === 'PARTIAL').length;
  const failed = results.filter((r) => r.verdict === 'FAIL').length;

  console.log(`\n== MOSIP integration: ${passed} pass, ${partial} partial, ${failed} fail (of ${results.length}) ==`);

  if (failed === 0 && partial === 0) {
    console.log(
      '\nAll five MOSIP integration capabilities are implemented and exercised.\n\n' +
        'This is NOT a claim of MOSIP certification, compliance, or partnership, and it is not\n' +
        'evidence of having run against a live MOSIP deployment. Each capability is verified\n' +
        'against a counterparty built to MOSIP\'s published behaviour -- and, for the proof\n' +
        'suites, against credentials generated by the reference implementations rather than by\n' +
        'this codebase. What remains unverified needs things CI cannot hold: a credential from a\n' +
        'real Inji Certify instance, a registered eSignet client, and a MISP partner agreement.\n' +
        'See docs/MOSIP.md, which states that boundary surface by surface.\n',
    );
    process.exit(0);
  }

  console.log(
    '\nMOSIP integration incomplete. This suite GATES the build, so a non-PASS above is a\n' +
      'capability a deployment may already be relying on that has stopped working.\n',
  );
  process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});