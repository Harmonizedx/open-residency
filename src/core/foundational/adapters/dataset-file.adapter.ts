import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { extname } from 'node:path';
import { load as loadYaml } from 'js-yaml';
import {
  FoundationalProvider,
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  ProviderConfig,
} from '../types';
import { getPath, parseCsv } from '../util';
import { applicantBindingFrom, mapIdentity } from '../mapping';

/**
 * A foundational provider that verifies against an IMPORTED register extract rather than a
 * live API. The dataset is a CSV, JSON, or YAML file the identity authority hands over (a
 * signed data dump), indexed once at init by a key field.
 *
 * Why this belongs in the platform: not every authority exposes a callable API. Some provide
 * a periodic extract; some pilots and air-gapped deployments have no connectivity at all. A
 * file source lets those deployments run the exact same residency/credential/SSO pipeline --
 * the source of truth is a file instead of an endpoint, and nothing downstream changes.
 *
 * A file match is a LOOKUP (the record exists), never proof the applicant owns it -- so, like
 * a REST lookup, it attests no applicant binding unless the config declares otherwise. Bind
 * the applicant at the enrolment desk.
 */
export class DatasetFileAdapter implements FoundationalProvider {
  readonly code: string;
  private cfg!: ProviderConfig;
  private pepper: string;
  private index = new Map<string, Record<string, unknown>>();

  constructor(code = 'DATASET_FILE', pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper') {
    this.code = code;
    this.pepper = pepper;
  }

  init(config: ProviderConfig): void {
    this.cfg = config;
    const ds = config.dataset;
    if (!ds?.path || !ds.keyField) {
      throw new Error(
        `${this.code}: dataset requires { path, keyField } in provider config`,
      );
    }
    const path = isAbsolute(ds.path) ? ds.path : resolve(process.cwd(), ds.path);
    const text = readFileSync(path, 'utf8');
    const records = this.parseRecords(text, ds.format, ds.recordsPath);

    this.index.clear();
    for (const rec of records) {
      const key = this.normKey(String(getPath(rec, ds.keyField) ?? ''));
      if (key) this.index.set(key, rec);
    }
  }

  private parseRecords(
    text: string,
    format: 'csv' | 'json' | 'yaml' | undefined,
    recordsPath?: string,
  ): Record<string, unknown>[] {
    const fmt = format ?? this.inferFormat();
    let data: unknown;
    if (fmt === 'csv') return parseCsv(text);
    if (fmt === 'yaml') data = loadYaml(text);
    else data = JSON.parse(text);

    const located = recordsPath ? getPath(data, recordsPath) : data;
    if (Array.isArray(located)) return located as Record<string, unknown>[];
    // A single-object dataset (or a keyed map of records) is accepted too.
    if (located && typeof located === 'object') {
      return Object.values(located as Record<string, unknown>).filter(
        (v): v is Record<string, unknown> => !!v && typeof v === 'object',
      );
    }
    return [];
  }

  private inferFormat(): 'csv' | 'json' | 'yaml' {
    const ext = extname(this.cfg.dataset?.path ?? '').toLowerCase();
    if (ext === '.csv') return 'csv';
    if (ext === '.yaml' || ext === '.yml') return 'yaml';
    return 'json';
  }

  private normKey(v: string): string {
    return this.cfg.dataset?.caseInsensitive ? v.trim().toLowerCase() : v.trim();
  }

  async verify(
    input: FoundationalVerificationInput,
  ): Promise<FoundationalVerificationResult> {
    const ds = this.cfg.dataset!;
    // Which submitted identifier is the lookup key: the named one, else the first submitted.
    const submitted = ds.identifierKey
      ? input.identifiers[ds.identifierKey]
      : Object.values(input.identifiers)[0];
    const record = submitted ? this.index.get(this.normKey(String(submitted))) : undefined;

    if (!record) {
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        reason: 'FOUNDATIONAL_NO_MATCH',
      };
    }

    // Optional demographic cross-check: every named field must also match the record,
    // so a bare key hit alone cannot pass when the config asks for corroboration.
    for (const { identifierKey, recordField } of ds.matchFields ?? []) {
      const want = this.normKey(String(input.identifiers[identifierKey] ?? ''));
      const have = this.normKey(String(getPath(record, recordField) ?? ''));
      if (!want || want !== have) {
        return {
          verified: false,
          providerCode: this.code,
          assuranceLevel: 'none',
          reason: 'FOUNDATIONAL_FIELD_MISMATCH',
        };
      }
    }

    return {
      verified: true,
      providerCode: this.code,
      assuranceLevel: this.cfg.assuranceOnSuccess ?? 'verified',
      identity: mapIdentity(this.cfg, this.code, this.pepper, record, input),
      applicantBinding: applicantBindingFrom(this.cfg, input),
    };
  }
}