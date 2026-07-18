import axios, { AxiosInstance } from 'axios';
import {
  FoundationalProvider,
  FoundationalVerificationInput,
  FoundationalVerificationResult,
  ProviderConfig,
} from '../types';
import { interpolate, interpolateObject, parseXml } from '../util';
import { buildAuthHeaders, resultFromBody } from '../mapping';

/**
 * A config-driven foundational provider for XML and SOAP national-ID services.
 *
 * Many government identity systems -- and most X-Road-style deployments -- expose SOAP/XML
 * rather than REST/JSON. This adapter is the JSON adapter's sibling: it issues the request,
 * parses the XML response into a plain object (namespace prefixes stripped by default), and
 * hands it to the SAME mapping module, so `verifiedFlag` and `responseMapping` dot-paths are
 * written exactly as they are for a REST provider -- they just address elements now.
 *
 * SOAP requests are sent by putting the envelope in `request.bodyRaw` (with `{identifiers.x}`
 * placeholders) and setting `request.contentType` (e.g. `text/xml` or `application/soap+xml`).
 * A plain XML-over-GET service just sets `request.method: GET` and a templated `request.path`.
 */
export class GenericXmlAdapter implements FoundationalProvider {
  readonly code: string;
  private cfg!: ProviderConfig;
  private http!: AxiosInstance;
  private pepper: string;

  constructor(code = 'GENERIC_XML', pepper = process.env.SUBJECT_PEPPER ?? 'dev-pepper') {
    this.code = code;
    this.pepper = pepper;
  }

  init(config: ProviderConfig): void {
    this.cfg = config;
    this.http = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeoutMs ?? 8000,
      // Keep the body as a raw string; we parse it ourselves rather than letting axios guess.
      responseType: 'text',
      transitional: { silentJSONParsing: false },
    });
  }

  async verify(
    input: FoundationalVerificationInput,
  ): Promise<FoundationalVerificationResult> {
    const req = this.cfg.request ?? {};
    const scope = { identifiers: input.identifiers, context: input.context ?? {} };
    const path = interpolate(req.path ?? '', scope);
    const headers: Record<string, string> = {
      ...interpolateObject(req.headers, scope),
      ...buildAuthHeaders(this.cfg),
    };

    try {
      let raw: unknown;
      if ((req.method ?? 'POST') === 'GET') {
        raw = (await this.http.get(path, { headers })).data;
      } else {
        // A SOAP/XML POST carries a raw envelope, not a form/JSON body.
        const body = interpolate(req.bodyRaw ?? '', scope);
        headers['content-type'] = req.contentType ?? 'text/xml; charset=utf-8';
        raw = (await this.http.post(path, body, { headers })).data;
      }

      const xml = typeof raw === 'string' ? raw : String(raw ?? '');
      const parsed = parseXml(xml, {
        stripNamespaces: this.cfg.xml?.stripNamespaces !== false,
      });
      return resultFromBody(this.cfg, this.code, this.pepper, parsed, input);
    } catch (err: unknown) {
      const status = axios.isAxiosError(err) ? err.response?.status : undefined;
      return {
        verified: false,
        providerCode: this.code,
        assuranceLevel: 'none',
        reason: status ? `PROVIDER_HTTP_${status}` : 'PROVIDER_UNREACHABLE',
      };
    }
  }
}
