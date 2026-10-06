// SPDX-License-Identifier: Apache-2.0
/* eslint-disable no-console */
/**
 * A resident's view of who has looked at their record.
 *
 * The property this file protects is that the resident sees everything that disclosed their
 * record and nothing that did not: every disclosure event targeting it, none targeting anyone
 * else, no write mistaken for a read, and no operator's identity -- staff have privacy too, and
 * the complaint route is the audit event id, not a name. Second property: the USSD form of the
 * same answer fits a feature-phone screen and answers only on the registered SIM's authority.
 * Third: the factor list is a deployment's choice, defaults to everything, and parses.
 */
import { AuditLog, InMemoryAuditStore } from '../src/core/audit/audit-log';
import { accessLogFor, accessLogFromEvents, classifyActor } from '../src/core/audit/access-log';
import { accessLogUssdSummary, handleUssd } from '../src/core/offline/ussd';
import { parseCountryConfig } from '../src/core/config/country-config';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}${detail ? `\n      ${detail}` : ''}`);
  }
}

async function main() {
  console.log('\n== resident access log ==\n');

  console.log('actors are reduced to kinds:');
  check('an operator id collapses to operator', classifyActor('admin.read', 'operator:desk-07').kind === 'operator');
  check('an api key collapses to operator', classifyActor('admin.read', 'apikey:k1').kind === 'operator');
  check('a verifier is a verifier', classifyActor('credential.verify', 'verifier').kind === 'verifier');
  const rp = classifyActor('oid4vp.presentation.verify', 'health-portal');
  check('a relying party is named by its client id, because the resident consented to it', rp.kind === 'relying_party' && rp.relyingParty === 'health-portal');
  check('a wallet collection is a wallet', classifyActor('oid4vci.credential.issue', 'wallet').kind === 'wallet');
  check('reading one\'s own log is the resident', classifyActor('resident.access.read', 'KD-X').kind === 'resident');

  console.log('\nthe log for one resident:');
  const audit = new AuditLog(new InMemoryAuditStore());
  const A = 'KD-ACC-0001-A';
  const B = 'KD-ACC-0002-B';
  await audit.record({ action: 'residency.issue', actor: 'operator:desk-07', target: A, outcome: 'success' });
  await audit.record({ action: 'admin.read', actor: 'operator:desk-07', target: A, outcome: 'success' });
  await audit.record({ action: 'admin.read', actor: 'operator:desk-09', target: B, outcome: 'success' });
  await audit.record({ action: 'credential.verify', actor: 'verifier', target: A, outcome: 'failure' });
  await audit.record({ action: 'oid4vp.presentation.verify', actor: 'health-portal', target: A, outcome: 'success' });
  await audit.record({ action: 'oid4vci.credential.issue', actor: 'wallet', target: A, outcome: 'success' });
  await audit.record({ action: 'residency.credential.transition', actor: 'operator:desk-07', target: A, outcome: 'success' });
  const entries = await accessLogFor(audit, A);
  check('four disclosures are listed, oldest first', entries.length === 4 && entries.every((e, i, a) => i === 0 || e.at >= a[i - 1].at));
  check('  in the right kinds', entries.map((e) => e.actorKind).join(',') === 'operator,verifier,relying_party,wallet');
  check('  the failed verification is included: an attempt to read is a disclosure attempt', entries.some((e) => e.action === 'credential.verify' && e.outcome === 'failure'));
  check('  writes to the record are not reads', !entries.some((e) => (e.action as string) === 'residency.issue' || (e.action as string) === 'residency.credential.transition'));
  const text = JSON.stringify(entries);
  check('  no operator identity anywhere', !text.includes('desk-07') && !text.includes('desk-09'));
  check('  nothing about the other resident', !text.includes(B));
  check('  the relying party is named', entries.some((e) => e.relyingParty === 'health-portal'));
  check('  every entry carries its audit event id', entries.every((e) => e.eventId && e.eventId.length > 8));
  check('the pure form agrees with the store-backed form', accessLogFromEvents(await audit.list({ target: A, limit: 100 }), A).length === 4);
  check('a resident with nothing recorded sees an empty list, not an error', (await accessLogFor(audit, 'KD-NONE-0000-0')).length === 0);

  console.log('\nthe USSD form:');
  const summary = accessLogUssdSummary(entries);
  check('fits a feature-phone screen', summary.length <= 160, String(summary.length));
  check('  states the count', /4 access/.test(summary));
  check('  names the service', /health-portal/.test(summary));
  check('  gives the most recent date', /Last: \d{4}-\d{2}-\d{2}/.test(summary));
  check('empty log reads plainly', accessLogUssdSummary([]) === 'No one has looked at your record.');
  const menu = handleUssd('');
  check('the menu offers it', /3\. Who has looked at my record/.test(menu.message));
  const prompt = handleUssd('3');
  check('  and asks for the id', prompt.continueSession && /Residency ID/.test(prompt.message));
  const act = handleUssd('3*kd-acc-0001-a');
  check('  then hands the controller an accessLogSummary action with the id upper-cased',
    act.action?.type === 'accessLogSummary' && act.action.residentId === 'KD-ACC-0001-A' && !act.continueSession);
  check('  whose default text reveals nothing', /If that residency ID is registered to this phone/.test(act.message));

  console.log('\nthe factor list is a deployment\'s choice:');
  const base = {
    countryCode: 'NG', countryName: 'Example', defaultSubnationalUnit: 'KD',
    foundational: { provider: 'MOCK', assuranceOnSuccess: 'verified' },
    residency: { minAssurance: 'verified' },
    credential: { issuerDid: 'did:web:example.org', issuerName: 'Example', type: 'StateResidencyCredential', validityDays: 1, context: [] },
    subnationalUnits: [{ code: 'KD', name: 'Kaduna', level: 'state' }],
  };
  const dflt = parseCountryConfig(base);
  check('default accepts all three, so nothing changes for an existing deployment', dflt.selfService.accessLogFactors.join(',') === 'presentation,ussd,otp');
  const noSms = parseCountryConfig({ ...base, selfService: { accessLogFactors: ['presentation', 'ussd'] } });
  check('a deployment that will not pay for messages keeps the two free ones', noSms.selfService.accessLogFactors.join(',') === 'presentation,ussd');
  let rejected = false;
  try { parseCountryConfig({ ...base, selfService: { accessLogFactors: [] } }); } catch { rejected = true; }
  check('an empty list is refused: some factor must exist or the surface is dead', rejected);

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
