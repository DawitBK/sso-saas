/**
 * Shared validation-failure formatting (Directive §6.8 — one validation
 * library, one failure-reporting convention across the platform). SSO has two
 * distinct response families (JSON API vs. rendered view-model), so this file
 * only owns the message text; parse.ts wires that text into each family's
 * existing convention rather than inventing a third envelope shape.
 */
import type { ZodError } from 'zod';

export function formatZodIssues(error: ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.join('.');
      return path ? `${path}: ${issue.message}` : issue.message;
    })
    .join('; ');
}

export function zodIssuesAsDetails(error: ZodError): Array<{ field?: string; message: string }> {
  return error.issues.map((issue) => ({
    field: issue.path.join('.') || undefined,
    message: issue.message,
  }));
}
