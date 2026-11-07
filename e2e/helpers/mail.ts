import { expect } from "@playwright/test";

const MAILPIT = process.env.E2E_MAILPIT_URL ?? "http://localhost:59025";

interface Summary { ID: string; Subject: string; Created: string }

// waitForMail polls mailpit for a mail to `to` created after `since` (and matching `subject`), so
// parallel tests never pick up each other's mail or an older one of their own.
export async function waitForMail(
  to: string,
  opts: { subject?: RegExp; since: Date; timeout?: number },
): Promise<{ subject: string; text: string }> {
  let found: Summary | undefined;
  await expect
    .poll(
      async () => {
        const r = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:"${to}"`)}`);
        if (!r.ok) throw new Error(`mailpit search: ${r.status}`);
        const { messages } = (await r.json()) as { messages: Summary[] };
        // mailpit stamps Created with ms precision; allow 5 s of clock skew between host and container
        found = messages.find((m) => new Date(m.Created).getTime() >= opts.since.getTime() - 5000 && (!opts.subject || opts.subject.test(m.Subject)));
        return found?.ID;
      },
      { message: `mail to ${to}${opts.subject ? ` matching ${opts.subject}` : ""}`, timeout: opts.timeout ?? 30_000 },
    )
    .toBeTruthy();
  const r = await fetch(`${MAILPIT}/api/v1/message/${found!.ID}`);
  if (!r.ok) throw new Error(`mailpit message ${found!.ID}: ${r.status}`);
  const m = (await r.json()) as { Subject: string; Text: string };
  return { subject: m.Subject, text: m.Text };
}

export function extractCode(text: string): string {
  const m = text.match(/(?:驗證碼是：|verification code is:)\s*(\d{6})/);
  if (!m) throw new Error(`no verification code in mail:\n${text}`);
  return m[1];
}

// extractLink returns path?query of the first URL in the mail whose path matches `path`. Mail links carry
// SX_BASE_URL (the e2e stack sets https://localhost:59443); pass the result to page.goto (baseURL supplies the origin).
export function extractLink(text: string, path: RegExp): string {
  for (const s of text.match(/https?:\/\/\S+/g) ?? []) {
    const u = new URL(s);
    if (path.test(u.pathname)) return u.pathname + u.search;
  }
  throw new Error(`no link matching ${path} in mail:\n${text}`);
}
