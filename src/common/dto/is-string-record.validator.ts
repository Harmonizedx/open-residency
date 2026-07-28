import { registerDecorator, ValidationArguments, ValidationOptions } from 'class-validator';

/**
 * Validates that a property is a plain object whose values are all strings, bounded in both
 * the number of keys and the length of each value.
 *
 * `@IsObject()` alone accepts `{ nin: { nested: 1 } }` — the values aren't checked — so a
 * `Record<string, string>` field (foundational identifiers) could carry non-string, nested,
 * or unbounded values straight to an adapter. This closes that at the edge and caps the
 * collection so a request cannot smuggle an oversized payload.
 */
export function IsStringRecord(
  opts: { maxKeys?: number; maxValueLength?: number } = {},
  validationOptions?: ValidationOptions,
) {
  const maxKeys = opts.maxKeys ?? 32;
  const maxValueLength = opts.maxValueLength ?? 512;
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: 'isStringRecord',
      target: object.constructor,
      propertyName,
      options: validationOptions,
      validator: {
        validate(value: unknown) {
          if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
          const entries = Object.entries(value as Record<string, unknown>);
          if (entries.length > maxKeys) return false;
          return entries.every(
            ([k, v]) => typeof k === 'string' && typeof v === 'string' && v.length <= maxValueLength,
          );
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} must be an object of string values (max ${maxKeys} keys, each <= ${maxValueLength} chars)`;
        },
      },
    });
  };
}
