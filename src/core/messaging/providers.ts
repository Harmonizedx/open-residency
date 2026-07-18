import axios, { AxiosInstance } from 'axios';
import {
  DeliveryResult,
  MessagingError,
  MessagingProvider,
  MessagingProviderCode,
  OutboundMessage,
  maskPhone,
} from './types';

/**
 * Messaging adapters.
 *
 * `GenericHttpProvider` is the real one; the named aggregators below are presets that
 * fill in its request shape. That is deliberate -- it keeps one code path under test and
 * means a deployment whose aggregator is not listed configures it in YAML instead of
 * waiting for us to write an adapter.
 */

export interface MessagingRequestConfig {
  method: 'GET' | 'POST';
  /** Path appended to baseUrl. May contain {to}, {body}, {sender} placeholders. */
  path: string;
  /** JSON body template. Values may contain the same placeholders. */
  bodyTemplate?: Record<string, string>;
  /** Form-encode the body instead of sending JSON. Several aggregators require this. */
  form?: boolean;
  headers?: Record<string, string>;
  /** Dot-path to the provider's message id in the response. */
  messageIdPath?: string;
  /**
   * Dot-path to a status field, plus the value that means accepted. When set, a 2xx whose
   * body reports a failure is treated as a failure -- several aggregators answer 200 with
   * an error payload, and without this a code that was never sent looks delivered.
   */
  successFlag?: { path: string; equals?: unknown };
}

export interface MessagingProviderConfig {
  provider: MessagingProviderCode;
  baseUrl?: string;
  /** Sender id / short code / from-number shown on the handset. */
  sender?: string;
  timeoutMs?: number;
  auth?: {
    type: 'none' | 'apiKey' | 'bearer' | 'basic';
    headerName?: string;
    secretEnv?: string;
    /** For basic auth (Twilio: account SID + auth token). */
    usernameEnv?: string;
  };
  request?: MessagingRequestConfig;
}

function readAt(obj: unknown, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (acc, k) => (acc && typeof acc === 'object' ? (acc as Record<string, unknown>)[k] : undefined),
      obj,
    );
}

function interpolate(template: string, msg: OutboundMessage, sender: string): string {
  return (
    template
      .replace(/\{to\}/g, msg.to)
      .replace(/\{body\}/g, msg.body)
      .replace(/\{sender\}/g, sender)
      .replace(/\{kind\}/g, msg.kind)
      // Some aggregators want their key in the request body rather than a header. This is
      // how it gets there without the secret ever appearing in a config file.
      .replace(/\{env:([A-Z0-9_]+)\}/g, (_m, name: string) => {
        const v = process.env[name];
        if (!v) {
          throw new MessagingError(
            `Messaging config references ${name}, which is not set in the environment`,
            'MESSAGING_SECRET_MISSING',
          );
        }
        return v;
      })
  );
}

/** Build auth headers from the environment. Secrets never live in config files. */
function authHeaders(cfg: MessagingProviderConfig): Record<string, string> {
  const auth = cfg.auth;
  if (!auth || auth.type === 'none') return {};
  const secret = auth.secretEnv ? process.env[auth.secretEnv] : undefined;
  if (!secret) {
    throw new MessagingError(
      `Messaging secret ${auth.secretEnv ?? '<unset>'} is not set in the environment`,
      'MESSAGING_SECRET_MISSING',
    );
  }
  switch (auth.type) {
    case 'apiKey':
      return { [auth.headerName ?? 'x-api-key']: secret };
    case 'bearer':
      return { authorization: `Bearer ${secret}` };
    case 'basic': {
      const user = auth.usernameEnv ? process.env[auth.usernameEnv] : undefined;
      if (!user) {
        throw new MessagingError(
          `Messaging username ${auth.usernameEnv ?? '<unset>'} is not set in the environment`,
          'MESSAGING_SECRET_MISSING',
        );
      }
      return {
        authorization: `Basic ${Buffer.from(`${user}:${secret}`).toString('base64')}`,
      };
    }
  }
}

export class GenericHttpProvider implements MessagingProvider {
  readonly code: MessagingProviderCode;
  private http: AxiosInstance;

  constructor(private cfg: MessagingProviderConfig) {
    this.code = cfg.provider;
    if (!cfg.baseUrl) {
      throw new MessagingError(
        `Messaging provider ${cfg.provider} needs a baseUrl`,
        'MESSAGING_CONFIG_INVALID',
      );
    }
    this.http = axios.create({
      baseURL: cfg.baseUrl,
      timeout: cfg.timeoutMs ?? 10_000,
    });
  }

  async send(msg: OutboundMessage): Promise<DeliveryResult> {
    const req = this.cfg.request;
    if (!req) {
      throw new MessagingError(
        `Messaging provider ${this.cfg.provider} needs a request block`,
        'MESSAGING_CONFIG_INVALID',
      );
    }
    const sender = this.cfg.sender ?? '';
    const path = interpolate(req.path, msg, sender);
    const body: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.bodyTemplate ?? {})) {
      body[k] = interpolate(v, msg, sender);
    }

    let data: unknown;
    try {
      const headers = {
        ...authHeaders(this.cfg),
        ...(req.headers ?? {}),
        ...(req.form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
      };
      const payload = req.form ? new URLSearchParams(body).toString() : body;
      const res =
        req.method === 'GET'
          ? await this.http.get(path, { headers, params: body })
          : await this.http.post(path, payload, { headers });
      data = res.data;
    } catch (e: any) {
      // Never let the aggregator's error echo the message body back into our logs: for an
      // OTP that would reintroduce exactly the leak this module exists to remove.
      const status = e?.response?.status;
      throw new MessagingError(
        `Messaging send to ${maskPhone(msg.to)} failed${status ? ` (HTTP ${status})` : ''}`,
        status ? `MESSAGING_HTTP_${status}` : 'MESSAGING_UNREACHABLE',
      );
    }

    if (req.successFlag) {
      const actual = readAt(data, req.successFlag.path);
      const expected = req.successFlag.equals;
      const ok =
        expected === undefined
          ? Boolean(actual)
          : String(actual).toLowerCase() === String(expected).toLowerCase();
      if (!ok) {
        throw new MessagingError(
          `Aggregator rejected the message to ${maskPhone(msg.to)} (${req.successFlag.path}=${String(actual)})`,
          'MESSAGING_REJECTED',
        );
      }
    }

    const id = req.messageIdPath ? readAt(data, req.messageIdPath) : undefined;
    return {
      channel: `sms:${this.cfg.provider.toLowerCase()}`,
      providerMessageId: id === undefined ? undefined : String(id),
    };
  }
}

/**
 * Development sender. Logs the message instead of delivering it.
 *
 * Now reachable only by setting `provider: LOG` explicitly. It used to be the wired-in
 * default, which is how a deployment could believe it had SMS working when every code was
 * going to stdout. It refuses to start unless the deployment has also acknowledged it, so
 * it cannot be inherited by accident from a copied config.
 */
export class LogProvider implements MessagingProvider {
  readonly code = 'LOG' as const;

  async send(msg: OutboundMessage): Promise<DeliveryResult> {
    // eslint-disable-next-line no-console
    console.warn(
      `[messaging] DEV PROVIDER: would send to ${maskPhone(msg.to)}: ${msg.body} ` +
        `-- configure a real messaging.provider before production.`,
    );
    return { channel: 'log' };
  }
}

/**
 * Presets for common aggregators. Each fills in the generic adapter's request shape; a
 * config may override any field, and an aggregator that is not listed is configured as
 * GENERIC_HTTP with its own request block.
 */
export const MESSAGING_PRESETS: Record<string, Partial<MessagingProviderConfig>> = {
  // https://africastalking.com -- apiKey header plus a username field in the form body.
  AFRICASTALKING: {
    baseUrl: 'https://api.africastalking.com',
    auth: { type: 'apiKey', headerName: 'apiKey', secretEnv: 'AFRICASTALKING_API_KEY' },
    request: {
      method: 'POST',
      path: '/version1/messaging',
      form: true,
      headers: { accept: 'application/json' },
      bodyTemplate: { username: '{sender}', to: '{to}', message: '{body}' },
      messageIdPath: 'SMSMessageData.Recipients.0.messageId',
    },
  },
  // Twilio: account SID + auth token as HTTP basic; the SID also appears in the path.
  TWILIO: {
    baseUrl: 'https://api.twilio.com',
    auth: {
      type: 'basic',
      usernameEnv: 'TWILIO_ACCOUNT_SID',
      secretEnv: 'TWILIO_AUTH_TOKEN',
    },
    request: {
      method: 'POST',
      path: '/2010-04-01/Accounts/{sender}/Messages.json',
      form: true,
      bodyTemplate: { To: '{to}', Body: '{body}' },
      messageIdPath: 'sid',
    },
  },
  // Termii: api key travels in the JSON body rather than a header.
  TERMII: {
    baseUrl: 'https://api.ng.termii.com',
    auth: { type: 'none' },
    request: {
      method: 'POST',
      path: '/api/sms/send',
      bodyTemplate: {
        to: '{to}',
        from: '{sender}',
        sms: '{body}',
        type: 'plain',
        channel: 'generic',
        api_key: '{env:TERMII_API_KEY}',
      },
      messageIdPath: 'message_id',
      successFlag: { path: 'code', equals: 'ok' },
    },
  },
};

/**
 * Apply a preset under an explicit config, then build the provider.
 *
 * Config wins over preset on every field, so a deployment can keep the preset's request
 * shape while pointing at a regional endpoint or a different secret env var.
 */
export function buildMessagingProvider(cfg: MessagingProviderConfig): MessagingProvider {
  if (cfg.provider === 'LOG') return new LogProvider();
  const preset = MESSAGING_PRESETS[cfg.provider] ?? {};
  const merged: MessagingProviderConfig = {
    ...preset,
    ...cfg,
    auth: cfg.auth ?? preset.auth,
    request: cfg.request ?? (preset.request as MessagingRequestConfig | undefined),
  };
  return new GenericHttpProvider(merged);
}
