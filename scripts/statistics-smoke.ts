/* eslint-disable no-console */
/**
 * Non-PII statistics export (DPG Standard indicator 6).
 *
 * The claim this suite defends is narrow and load-bearing: the extraction surface we point
 * a DPG reviewer at yields aggregate, non-proprietary, disclosure-controlled output, and
 * cannot yield a name. Each assertion below is one half of that claim -- including the
 * suppression arithmetic, which is the part that is easy to get subtly wrong and
 * impossible to notice by reading the output.
 */
import {
  aggregateResidency,
  project,
  toCsv,
  StatisticsInput,
} from '../src/core/statistics/aggregate';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}`);
  }
}

/** Build `n` identical residents in one cell. */
function cell(n: number, dims: Partial<StatisticsInput> = {}): StatisticsInput[] {
  const base: StatisticsInput = {
    countryCode: 'NG',
    subnationalUnit: 'KT',
    providerCode: 'MOCK',
    assuranceLevel: 'verified',
    provisional: false,
    ...dims,
  };
  return Array.from({ length: n }, () => ({ ...base }));
}

const AT = '2026-01-01T00:00:00.000Z';

async function main() {
  console.log('\n== OpenResidency non-PII statistics export ==\n');

  // --- The projection is the guarantee: PII must not survive it ---
  const fullRecord = {
    id: 'uuid-1',
    residentId: 'NG-KT-000123',
    subjectRef: 'tok_abc',
    countryCode: 'NG',
    subnationalUnit: 'KT',
    providerCode: 'MOCK',
    assuranceLevel: 'verified',
    provisional: false,
    person: {
      fullName: 'Amina Bello',
      givenName: 'Amina',
      familyName: 'Bello',
      dateOfBirth: '1990-04-02',
      gender: 'female',
    },
  };
  const projected = project(fullRecord);
  const serialized = JSON.stringify(projected);
  check(
    'the projection keeps only the five categorical dimensions',
    Object.keys(projected).sort().join(',') ===
      'assuranceLevel,countryCode,providerCode,provisional,subnationalUnit',
  );
  check(
    'no name, date of birth, gender, residentId or subjectRef survives the projection',
    !serialized.includes('Amina') &&
      !serialized.includes('Bello') &&
      !serialized.includes('1990-04-02') &&
      !serialized.includes('female') &&
      !serialized.includes('NG-KT-000123') &&
      !serialized.includes('tok_abc'),
  );

  // --- Aggregation groups by the full dimension tuple ---
  const grouped = aggregateResidency(
    [...cell(9), ...cell(7, { subnationalUnit: 'KN' }), ...cell(6, { provisional: true })],
    { generatedAt: AT },
  );
  check('distinct dimension tuples become distinct cells', grouped.cells.length === 3);
  check('residents in the same cell are counted together', grouped.totalResidents === 22);
  check(
    'cells at or above the threshold publish their count',
    grouped.cells.every((c) => !c.suppressed && typeof c.count === 'number'),
  );
  check('the generated timestamp is the one supplied', grouped.generatedAt === AT);

  // --- Primary suppression ---
  const small = aggregateResidency([...cell(40), ...cell(30, { subnationalUnit: 'KN' }), ...cell(2, { subnationalUnit: 'ZM' })], {
    generatedAt: AT,
  });
  const zm = small.cells.find((c) => c.subnationalUnit === 'ZM');
  check('a cell below the threshold is suppressed', zm?.suppressed === true);
  check('a suppressed cell carries no count at all', zm?.count === null);

  // --- Complementary suppression: the subtraction attack ---
  //
  // 40 + 30 + 2 = 72. Publishing "40, 30, withheld" next to a total of 72 gives the
  // withheld cell away. A second cell must go with it.
  const suppressedCount = small.cells.filter((c) => c.suppressed).length;
  check(
    'a lone suppressed cell drags a second one with it (no subtraction attack)',
    suppressedCount === 2,
  );
  check(
    'the complementary victim is the smallest survivor, not an arbitrary one',
    small.cells.find((c) => c.subnationalUnit === 'KN')?.suppressed === true &&
      small.cells.find((c) => c.subnationalUnit === 'KT')?.suppressed === false,
  );
  check(
    'the total still counts suppressed residents, so it stays truthful',
    small.totalResidents === 72,
  );

  // --- The degenerate case: the total must not undo the suppression ---
  const lone = aggregateResidency(cell(3), { generatedAt: AT });
  check('a single small cell is suppressed', lone.cells[0]?.suppressed === true);
  check(
    'and the grand total is withheld too, or it would hand the cell straight back',
    lone.totalResidents === null,
  );

  // A total at or above the threshold is publishable even when every cell is withheld:
  // the reader learns the sum, not the split.
  const allSuppressed = aggregateResidency([...cell(4), ...cell(4, { subnationalUnit: 'KN' })], {
    generatedAt: AT,
  });
  check(
    'a publishable total survives even when every cell is suppressed',
    allSuppressed.cells.every((c) => c.suppressed) && allSuppressed.totalResidents === 8,
  );

  // --- Threshold is configurable, including off ---
  const noSuppression = aggregateResidency(cell(1), {
    suppressionThreshold: 0,
    generatedAt: AT,
  });
  check(
    'a zero threshold disables suppression for deployments that want raw counts',
    noSuppression.cells[0]?.count === 1 && noSuppression.totalResidents === 1,
  );

  // --- CSV is RFC 4180, not "join with commas" ---
  const csv = toCsv(grouped);
  const lines = csv.split('\r\n');
  check(
    'CSV leads with a header row naming every column',
    lines[0] ===
      'countryCode,subnationalUnit,providerCode,assuranceLevel,provisional,count,suppressed',
  );
  check('CSV rows are CRLF-terminated per RFC 4180', csv.endsWith('\r\n') && lines.length === 5);
  check('CSV carries one row per cell', lines.filter((l) => l.length > 0).length === 4);

  const suppressedCsv = toCsv(lone);
  check(
    'a suppressed count is an empty CSV field, flagged by the suppressed column',
    suppressedCsv.split('\r\n')[1] === 'NG,KT,MOCK,verified,false,,true',
  );

  // Field escaping. Subnational unit codes are validated upstream, but the serializer is
  // the wrong place to assume that: a CSV writer that cannot quote is a defect waiting for
  // a new dimension to be added.
  const quoted = toCsv(
    aggregateResidency(cell(9, { providerCode: 'A,B "C"' }), { generatedAt: AT }),
  );
  check(
    'a field containing a comma and quotes is escaped, not smuggled into the next column',
    quoted.split('\r\n')[1] === 'NG,KT,"A,B ""C""",verified,false,9,false',
  );

  console.log(`\n== Result: ${pass} passed, ${fail} failed ==\n`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
