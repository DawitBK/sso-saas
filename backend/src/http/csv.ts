/**
 * CSV for the console's exports (users, audit trail, sign-in log).
 *
 * A value that starts with = + - @ or a control character would be EXECUTED by Excel or Sheets when someone opens the file (CSV
 * injection: a person's name or a sign-in address becomes a formula that exfiltrates data or runs a command), so it is prefixed with an
 * apostrophe. The file starts with a byte-order mark so Excel reads it as UTF-8 (names with accents survive).
 */
import type { Response } from 'express';

export function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function csvRow(values: unknown[]): string {
  return values.map(csvCell).join(',');
}

/** Send `lines` (header first) as a downloadable file. */
export function sendCsv(res: Response, filename: string, lines: string[], headers: Record<string, string> = {}): void {
  res
    .status(200)
    .set({
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': `attachment; filename="${filename}"`,
      'cache-control': 'no-store',
      ...headers,
    })
    .send(`\uFEFF${lines.join('\r\n')}\r\n`);
}
