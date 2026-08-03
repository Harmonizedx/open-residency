// SPDX-License-Identifier: Apache-2.0
/**
 * Non-PII statistical aggregation over the Resident Registry.
 *
 * This exists to answer DPG Standard indicator 6 ("mechanism for extracting data") with
 * something real: a documented way to get non-PII data out of the system in a
 * non-proprietary format (JSON and RFC 4180 CSV). The registry itself is PII -- a
 * `residentId` is a pseudonymous identifier and still personal data -- so the extractable
 * surface is deliberately aggregate-only.
 *
 * The type system carries that guarantee rather than a comment asking nicely: this module
 * consumes `StatisticsInput`, which has no name, date of birth, gender, contact detail, or
 * identifier field on it at all. `project()` is the single narrowing point, so there is one
 * place to review when asking "can a name reach the export?".
 */

/**
 * The only resident attributes the aggregator is allowed to see. Every field is
 * categorical; none of them identifies a person on its own.
 */
export interface StatisticsInput {
  countryCode: string;
  subnationalUnit: string;
  providerCode: string;
  assuranceLevel: string;
  provisional: boolean;
}

/** Narrow a full registry record down to the non-PII dimensions. The only way in. */
export function project(record: {
  countryCode: string;
  subnationalUnit: string;
  providerCode: string;
  assuranceLevel: string;
  provisional: boolean;
}): StatisticsInput {
  return {
    countryCode: record.countryCode,
    subnationalUnit: record.subnationalUnit,
    providerCode: record.providerCode,
    assuranceLevel: record.assuranceLevel,
    provisional: record.provisional,
  };
}

/** One aggregated cell. `count` is null exactly when `suppressed` is true. */
export interface ResidencyCell {
  countryCode: string;
  subnationalUnit: string;
  providerCode: string;
  assuranceLevel: string;
  provisional: boolean;
  count: number | null;
  suppressed: boolean;
}

export interface ResidencyStatistics {
  generatedAt: string;
  /** Cells counting fewer residents than this are withheld. */
  suppressionThreshold: number;
  /**
   * Total across every cell, including suppressed ones. Null when the total is itself
   * below the threshold -- see `aggregateResidency` for why publishing it would undo the
   * cell suppression.
   */
  totalResidents: number | null;
  countries: number;
  cells: ResidencyCell[];
}

export interface AggregateOptions {
  /**
   * Minimum cell size to publish. A ward with one resident in it is re-identifiable by
   * anyone who knows their neighbours, so small cells are withheld rather than published.
   * Default 5, the common statistical-disclosure floor.
   */
  suppressionThreshold?: number;
  /** Injected so the caller controls the clock (and tests stay deterministic). */
  generatedAt?: string;
}

const KEY_SEPARATOR = '\0';

function cellKey(r: StatisticsInput): string {
  return [
    r.countryCode,
    r.subnationalUnit,
    r.providerCode,
    r.assuranceLevel,
    String(r.provisional),
  ].join(KEY_SEPARATOR);
}

/**
 * Aggregate residents into published cells, applying statistical disclosure control.
 *
 * Suppression is two-stage, because primary suppression alone leaks. If a country has
 * cells of 40, 30 and 2 and we publish "40, 30, withheld" alongside a total of 72, the
 * withheld cell is a subtraction away. So whenever a country group ends up with exactly
 * one suppressed cell, the next-smallest cell is suppressed too (complementary
 * suppression) -- with two unknowns the subtraction no longer isolates either.
 *
 * The grand total needs the same treatment for the degenerate case. A deployment with a
 * single cell in it has `total === that cell`, so publishing the total hands back the
 * value the suppression just withheld. Withholding a total that is itself below the
 * threshold closes that exactly: a lone cell is suppressed only when it is under the
 * threshold, which is precisely when the total is too.
 *
 * This is honest disclosure control, not a proof: a determined attacker correlating
 * several releases over time, or one who already knows most of the population, can still
 * narrow a cell. Deployers publishing this openly should say so, and should not treat the
 * threshold as a substitute for a disclosure review.
 */
export function aggregateResidency(
  residents: StatisticsInput[],
  opts: AggregateOptions = {},
): ResidencyStatistics {
  const threshold = opts.suppressionThreshold ?? 5;

  const counts = new Map<string, { dims: StatisticsInput; count: number }>();
  for (const r of residents) {
    const key = cellKey(r);
    const existing = counts.get(key);
    if (existing) existing.count++;
    else counts.set(key, { dims: r, count: 1 });
  }

  const cells: ResidencyCell[] = [...counts.values()].map(({ dims, count }) => ({
    countryCode: dims.countryCode,
    subnationalUnit: dims.subnationalUnit,
    providerCode: dims.providerCode,
    assuranceLevel: dims.assuranceLevel,
    provisional: dims.provisional,
    count,
    suppressed: false,
  }));

  // Stable ordering: the export is a file people diff between releases.
  cells.sort(
    (a, b) =>
      a.countryCode.localeCompare(b.countryCode) ||
      a.subnationalUnit.localeCompare(b.subnationalUnit) ||
      a.providerCode.localeCompare(b.providerCode) ||
      a.assuranceLevel.localeCompare(b.assuranceLevel) ||
      Number(a.provisional) - Number(b.provisional),
  );

  const byCountry = new Map<string, ResidencyCell[]>();
  for (const cell of cells) {
    const group = byCountry.get(cell.countryCode);
    if (group) group.push(cell);
    else byCountry.set(cell.countryCode, [cell]);
  }

  for (const group of byCountry.values()) {
    // Primary: anything under the threshold.
    for (const cell of group) {
      if ((cell.count ?? 0) < threshold) cell.suppressed = true;
    }
    // Complementary: one lone suppressed cell is recoverable by subtraction, so take the
    // smallest surviving cell with it. Nothing to do when a group is already fully
    // suppressed, or when none of it was.
    const suppressedCount = group.filter((c) => c.suppressed).length;
    if (suppressedCount === 1 && group.length > 1) {
      const smallestSurvivor = group
        .filter((c) => !c.suppressed)
        .sort((a, b) => (a.count ?? 0) - (b.count ?? 0))[0];
      if (smallestSurvivor) smallestSurvivor.suppressed = true;
    }
  }

  const total = cells.reduce((sum, c) => sum + (c.count ?? 0), 0);
  for (const cell of cells) {
    if (cell.suppressed) cell.count = null;
  }

  return {
    generatedAt: opts.generatedAt ?? new Date().toISOString(),
    suppressionThreshold: threshold,
    totalResidents: total < threshold ? null : total,
    countries: byCountry.size,
    cells,
  };
}

const CSV_COLUMNS = [
  'countryCode',
  'subnationalUnit',
  'providerCode',
  'assuranceLevel',
  'provisional',
  'count',
  'suppressed',
] as const;

/** RFC 4180 field escaping: quote when the value carries a comma, quote, CR or LF. */
function csvField(value: string): string {
  if (/[",\r\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

/**
 * Serialize to RFC 4180 CSV. A suppressed cell's `count` is an empty field: withheld, as
 * opposed to a number the reader is entitled to. The `suppressed` column says which case
 * it is without the reader having to infer it from a blank.
 */
export function toCsv(report: ResidencyStatistics): string {
  const lines = [CSV_COLUMNS.join(',')];
  for (const cell of report.cells) {
    lines.push(
      [
        csvField(cell.countryCode),
        csvField(cell.subnationalUnit),
        csvField(cell.providerCode),
        csvField(cell.assuranceLevel),
        String(cell.provisional),
        cell.count === null ? '' : String(cell.count),
        String(cell.suppressed),
      ].join(','),
    );
  }
  // Trailing newline: POSIX text file, and it keeps `diff` quiet.
  return lines.join('\r\n') + '\r\n';
}
