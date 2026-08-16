/* eslint-disable no-console */
/**
 * Smoke test for the multi-source foundational layer: XML/SOAP and imported-dataset
 * providers, alongside the raw parsers they rely on. Runs fully offline -- the XML path is
 * exercised against a throwaway local HTTP server, the dataset path against real files.
 */
import { createServer, Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProviderRegistry } from '../src/core/foundational/registry';
import { parseXml, parseCsv } from '../src/core/foundational/util';
import { ProviderConfig } from '../src/core/foundational/types';

let pass = 0;
let fail = 0;
function check(name: string, cond: boolean): void {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}`);
  }
}

const SOAP_MATCH = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <ns2:VerifyIdentityResponse xmlns:ns2="urn:example:id">
      <match>true</match>
      <person>
        <nationalId>23456789012</nationalId>
        <firstName>Amina</firstName>
        <lastName>Bello</lastName>
        <dob>1991-03-14</dob>
        <sex>F</sex>
        <residenceState><![CDATA[Katsina]]></residenceState>
      </person>
    </ns2:VerifyIdentityResponse>
  </soap:Body>
</soap:Envelope>`;

const SOAP_NOMATCH = `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body><VerifyIdentityResponse><match>false</match></VerifyIdentityResponse></soap:Body>
</soap:Envelope>`;

function xmlConfig(baseUrl: string): ProviderConfig {
  return {
    code: 'GENERIC_XML',
    baseUrl,
    responseFormat: 'xml',
    request: {
      method: 'POST',
      path: '/IdentityService',
      contentType: 'application/soap+xml',
      bodyRaw:
        '<Envelope><Body><VerifyIdentity><nationalId>{identifiers.nationalId}</nationalId></VerifyIdentity></Body></Envelope>',
    },
    verifiedFlag: { path: 'Envelope.Body.VerifyIdentityResponse.match', equals: true },
    responseMapping: {
      givenName: 'Envelope.Body.VerifyIdentityResponse.person.firstName',
      familyName: 'Envelope.Body.VerifyIdentityResponse.person.lastName',
      dateOfBirth: 'Envelope.Body.VerifyIdentityResponse.person.dob',
      residenceAdminUnit: 'Envelope.Body.VerifyIdentityResponse.person.residenceState',
    },
    assuranceOnSuccess: 'verified',
    extra: { subjectSourcePath: 'Envelope.Body.VerifyIdentityResponse.person.nationalId' },
  };
}

async function main(): Promise<void> {
  console.log('\n== OpenResidency multi-source foundational smoke test ==\n');

  // --- parseXml unit behaviour ---
  console.log('parseXml:');
  const parsed = parseXml(SOAP_MATCH) as any;
  check('strips namespace prefixes (ns2: -> plain)', 'VerifyIdentityResponse' in parsed.Envelope.Body);
  check('leaf element collapses to its text', parsed.Envelope.Body.VerifyIdentityResponse.person.firstName === 'Amina');
  check('CDATA is read as text', parsed.Envelope.Body.VerifyIdentityResponse.person.residenceState === 'Katsina');
  check('flag element reads "true"', parsed.Envelope.Body.VerifyIdentityResponse.match === 'true');

  const arr = parseXml('<r><item>a</item><item>b</item><item>c</item></r>') as any;
  check('repeated elements fold into an array', Array.isArray(arr.r.item) && arr.r.item.length === 3 && arr.r.item[2] === 'c');
  const attrs = parseXml('<r><p id="7" role="head">Ada</p><self/></r>') as any;
  check('attributes map as @_name', attrs.r.p['@_id'] === '7' && attrs.r.p['@_role'] === 'head');
  check('element with attrs keeps #text', attrs.r.p['#text'] === 'Ada');
  check('self-closing tag yields empty leaf', attrs.r.self === '');
  const ent = parseXml('<r><v>a &amp; b &lt; c</v></r>') as any;
  check('entities decode', ent.r.v === 'a & b < c');
  const nons = parseXml('<ns2:Body>keep:me</ns2:Body>', { stripNamespaces: false }) as any;
  check('stripNamespaces:false keeps the prefixed element name', nons['ns2:Body'] === 'keep:me');

  // --- parseCsv unit behaviour ---
  console.log('\nparseCsv:');
  const csv = parseCsv('a,b,c\n1,"two, still two",3\n"line\nbreak",y,z\n');
  check('quoted comma stays one field', csv[0].b === 'two, still two');
  check('quoted newline stays one field', csv[1].a === 'line\nbreak');
  check('columns map by header', csv[0].a === '1' && csv[0].c === '3');

  // --- XML provider over a real local server ---
  console.log('\nGENERIC_XML provider (live local SOAP server):');
  let lastContentType = '';
  let lastBody = '';
  const server: Server = createServer((req, res) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      lastContentType = String(req.headers['content-type'] ?? '');
      lastBody = data;
      const wantsNoMatch = data.includes('00000000000');
      res.setHeader('content-type', 'application/soap+xml; charset=utf-8');
      res.end(wantsNoMatch ? SOAP_NOMATCH : SOAP_MATCH);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const registry = new ProviderRegistry('smoke-pepper');
  const xml = registry.resolve(xmlConfig(baseUrl));

  const ok = await xml.verify({ countryCode: 'XM', identifiers: { nationalId: '23456789012', lastName: 'Bello' } });
  check('verified match', ok.verified === true);
  check('assurance is verified', ok.assuranceLevel === 'verified');
  check('given name mapped from XML', ok.identity?.givenName === 'Amina');
  check('family name mapped from XML', ok.identity?.familyName === 'Bello');
  check('residence mapped (CDATA) from XML', ok.identity?.residenceAdminUnit === 'Katsina');
  check('subjectRef is tokenized, not the raw id', !!ok.identity && ok.identity.subjectRef.startsWith('generic_xml:') && !ok.identity.subjectRef.includes('23456789012'));
  check('lookup attests NO applicant binding', ok.applicantBinding === undefined);
  check('SOAP envelope was posted with soap content-type', lastContentType.includes('soap+xml') && lastBody.includes('23456789012'));

  const no = await xml.verify({ countryCode: 'XM', identifiers: { nationalId: '00000000000' } });
  check('non-match verified=false', no.verified === false && no.reason === 'FOUNDATIONAL_NO_MATCH');

  await new Promise<void>((r) => server.close(() => r()));

  // --- Transient gateway failure: retried, not refused ------------------------
  //
  // A national ID gateway is another government's server on another government's network.
  // Before this, one dropped connection refused the applicant outright and the desk had to
  // key the whole application in again. What must NOT happen is retrying a definitive
  // answer: a 4xx refusal costs a paid call to be told the same thing, and on a metered
  // contract it spends the budget of the citizens queued behind this one.
  console.log('\nGateway retry (transient failure recovers, definitive failure does not):');
  {
    let hits = 0;
    const flaky: Server = createServer((req, res) => {
      let data = '';
      req.on('data', (c) => (data += c));
      req.on('end', () => {
        hits++;
        // Fail the first two attempts the way a real gateway does, then answer.
        if (hits === 1) {
          res.socket?.destroy(); // connection reset: no response at all
          return;
        }
        if (hits === 2) {
          res.statusCode = 503;
          res.end('upstream unavailable');
          return;
        }
        res.setHeader('content-type', 'application/soap+xml; charset=utf-8');
        res.end(SOAP_MATCH);
      });
    });
    await new Promise<void>((r) => flaky.listen(0, '127.0.0.1', r));
    const flakyPort = (flaky.address() as AddressInfo).port;
    const flakyCfg = xmlConfig(`http://127.0.0.1:${flakyPort}`);
    const retried = registry.resolve({
      ...flakyCfg,
      retry: { attempts: 3, baseDelayMs: 1, maxDelayMs: 5 },
    } as ProviderConfig);

    const recovered = await retried.verify({
      countryCode: 'XM',
      identifiers: { nationalId: '23456789012', lastName: 'Bello' },
    });
    check('a reset connection then a 503 still verifies on the third attempt', recovered.verified === true);
    check('it took exactly three attempts', hits === 3);

    // A 4xx is the gateway understanding us and saying no. One call, no retry.
    hits = 0;
    const refusing: Server = createServer((_req, res) => {
      hits++;
      res.statusCode = 400;
      res.end('bad request');
    });
    await new Promise<void>((r) => refusing.listen(0, '127.0.0.1', r));
    const refusingPort = (refusing.address() as AddressInfo).port;
    const notRetried = registry.resolve({
      ...xmlConfig(`http://127.0.0.1:${refusingPort}`),
      retry: { attempts: 3, baseDelayMs: 1, maxDelayMs: 5 },
    } as ProviderConfig);
    const refused = await notRetried.verify({ countryCode: 'XM', identifiers: { nationalId: '1' } });
    check('a 400 is NOT retried (one call only)', hits === 1);
    check('and is reported with its status', refused.verified === false && refused.reason === 'PROVIDER_HTTP_400');

    // Exhausting the attempts still reports the honest reason rather than a retry artefact.
    hits = 0;
    const down: Server = createServer((_req, res) => {
      hits++;
      res.statusCode = 502;
      res.end('bad gateway');
    });
    await new Promise<void>((r) => down.listen(0, '127.0.0.1', r));
    const downPort = (down.address() as AddressInfo).port;
    const exhausted = registry.resolve({
      ...xmlConfig(`http://127.0.0.1:${downPort}`),
      retry: { attempts: 2, baseDelayMs: 1, maxDelayMs: 5 },
    } as ProviderConfig);
    const gaveUp = await exhausted.verify({ countryCode: 'XM', identifiers: { nationalId: '1' } });
    check('a gateway that stays down is retried to the limit then reported', hits === 2);
    check('the reported reason is the real one', gaveUp.verified === false && gaveUp.reason === 'PROVIDER_HTTP_502');

    await new Promise<void>((r) => flaky.close(() => r()));
    await new Promise<void>((r) => refusing.close(() => r()));
    await new Promise<void>((r) => down.close(() => r()));
  }

  // --- Dataset provider: CSV (committed), plus JSON and YAML temp files ---
  console.log('\nDATASET_FILE / IMPORT provider:');
  const dir = mkdtempSync(join(tmpdir(), 'openres-ds-'));
  try {
    const csvCfg: ProviderConfig = {
      code: 'DATASET_FILE',
      dataset: {
        path: 'config/datasets/example-registry.csv',
        format: 'csv',
        keyField: 'national_id',
        identifierKey: 'nin',
        matchFields: [{ identifierKey: 'lastName', recordField: 'last_name' }],
        caseInsensitive: true,
      },
      responseMapping: {
        givenName: 'first_name',
        familyName: 'last_name',
        residenceAdminUnit: 'residence_state',
        originAdminUnit: 'origin_state',
      },
      assuranceOnSuccess: 'verified',
      extra: { subjectSourcePath: 'national_id' },
    };
    const ds = registry.resolve(csvCfg);
    const hit = await ds.verify({ countryCode: 'XF', identifiers: { nin: '34567890123', lastName: 'Okeke' } });
    check('CSV match verified', hit.verified === true);
    check('CSV mapped given name', hit.identity?.givenName === 'Chidi');
    check('CSV residence kept, origin kept separate', hit.identity?.residenceAdminUnit === 'Katsina' && hit.identity?.originAdminUnit === 'Anambra');
    check('CSV subjectRef tokenized', !!hit.identity && !hit.identity.subjectRef.includes('34567890123'));
    check('CSV file lookup attests no binding', hit.applicantBinding === undefined);

    const missKey = await ds.verify({ countryCode: 'XF', identifiers: { nin: '99999999999', lastName: 'Okeke' } });
    check('unknown key -> no match', missKey.verified === false && missKey.reason === 'FOUNDATIONAL_NO_MATCH');
    const missField = await ds.verify({ countryCode: 'XF', identifiers: { nin: '34567890123', lastName: 'Wrongname' } });
    check('key hit but demographic mismatch -> rejected', missField.verified === false && missField.reason === 'FOUNDATIONAL_FIELD_MISMATCH');
    check('case-insensitive surname match', (await ds.verify({ countryCode: 'XF', identifiers: { nin: '34567890123', lastName: 'okeke' } })).verified === true);

    // JSON with a nested records path
    const jsonPath = join(dir, 'reg.json');
    writeFileSync(jsonPath, JSON.stringify({ data: { residents: [{ id: 'A1', surname: 'Musa' }] } }));
    const jsonDs = registry.resolve({
      code: 'IMPORT',
      dataset: { path: jsonPath, format: 'json', recordsPath: 'data.residents', keyField: 'id' },
      responseMapping: { familyName: 'surname' },
      assuranceOnSuccess: 'verified',
    });
    const jhit = await jsonDs.verify({ countryCode: 'XF', identifiers: { id: 'A1' } });
    check('IMPORT alias resolves to dataset adapter', jhit.verified === true && jhit.providerCode === 'IMPORT');
    check('JSON nested recordsPath located', jhit.identity?.familyName === 'Musa');

    // YAML dataset at the root
    const yamlPath = join(dir, 'reg.yaml');
    writeFileSync(yamlPath, '- { id: B2, surname: Yusuf }\n- { id: B3, surname: Ali }\n');
    const yamlDs = registry.resolve({
      code: 'DATASET_FILE',
      dataset: { path: yamlPath, keyField: 'id' }, // format inferred from .yaml
      responseMapping: { familyName: 'surname' },
      assuranceOnSuccess: 'verified',
    });
    const yhit = await yamlDs.verify({ countryCode: 'XF', identifiers: { id: 'B3' } });
    check('YAML dataset (format inferred) matches', yhit.verified === true && yhit.identity?.familyName === 'Ali');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  console.log(`\n== ${pass} passed, ${fail} failed ==\n`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
