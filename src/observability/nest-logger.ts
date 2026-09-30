// SPDX-License-Identifier: Apache-2.0
import { LoggerService } from '@nestjs/common';
import type { Logger } from 'pino';

/**
 * Routes Nest's logger -- the framework's own messages and every `new Logger('Context')` in
 * the application -- into the root pino logger, so the process emits one log shape rather than
 * Nest's coloured text beside JSON. Nest passes the context name as the LAST optional
 * argument; `error()` may put a stack string before it.
 */
export class PinoNestLogger implements LoggerService {
  constructor(private readonly root: Logger) {}

  log(message: unknown, ...rest: unknown[]): void {
    this.emit('info', message, rest);
  }
  error(message: unknown, ...rest: unknown[]): void {
    this.emit('error', message, rest);
  }
  warn(message: unknown, ...rest: unknown[]): void {
    this.emit('warn', message, rest);
  }
  debug(message: unknown, ...rest: unknown[]): void {
    this.emit('debug', message, rest);
  }
  verbose(message: unknown, ...rest: unknown[]): void {
    this.emit('trace', message, rest);
  }
  fatal(message: unknown, ...rest: unknown[]): void {
    this.emit('fatal', message, rest);
  }

  private emit(
    level: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace',
    message: unknown,
    rest: unknown[],
  ): void {
    const params = [...rest];
    const context =
      params.length && typeof params[params.length - 1] === 'string'
        ? (params.pop() as string)
        : undefined;
    const fields: Record<string, unknown> = {};
    if (context) fields.context = context;
    if (params.length) fields.detail = params;

    if (message instanceof Error) {
      this.root[level]({ ...fields, err: message }, message.message);
    } else if (typeof message === 'object' && message !== null) {
      this.root[level]({ ...fields, ...(message as Record<string, unknown>) }, 'log');
    } else {
      this.root[level](fields, String(message));
    }
  }
}
