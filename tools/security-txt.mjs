// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make site-check — the site's security.txt (RFC 9116), held so it cannot quietly go out of date.
//
// A security.txt is a promise with an end date written in it: "Expires". A file past that date tells a researcher
// its contacts may no longer be read, and RFC 9116 says to treat it as stale. Nobody remembers to renew a text
// file, so this fails the gate sixty days BEFORE the date instead of leaving it to be found after.
//
//   node tools/security-txt.mjs            the file must be present, complete and good for at least 60 more days
//   node tools/security-txt.mjs --drill    the witness
//
// It holds: a Contact that is the repository's private advisory form (the first choice in SECURITY.md) and one that
// is the public mailbox; Expires, once, in the future by 60 days and by no more than a year (the RFC's advice);
// Canonical, equal to the address the file is served at; Policy, pointing at a SECURITY.md that exists here.
//
// WITNESS: --drill runs the same checks on four broken copies (expired, expiring in a month, no Contact, a
// Canonical for another host) and must refuse each for its own reason, and must accept the file as committed.
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const FILE = ROOT + "site/.well-known/security.txt";
const CANONICAL = "https://ainra.org/.well-known/security.txt";
const DAY = 86_400_000;

export function problems(text, now = Date.now()) {
  const out = [], fields = {};
  for (const line of text.split("\n")) {
    const m = /^([A-Za-z-]+):\s*(\S.*)$/.exec(line.trim()); if (!m || line.startsWith("#")) continue;
    (fields[m[1].toLowerCase()] ??= []).push(m[2].trim());
  }
  const contacts = fields.contact ?? [];
  if (!contacts.length) out.push("no Contact");
  if (!contacts.some((c) => c.startsWith("https://github.com/AINRA-organization/ainra/security/advisories"))) out.push("no Contact for the private advisory form");
  if (!contacts.some((c) => c === "mailto:info@ainra.org")) out.push("no Contact for the public mailbox");
  if (contacts.some((c) => !/^(https:\/\/|mailto:)/.test(c))) out.push("a Contact that is neither https nor mailto");
  const exp = fields.expires ?? [];
  if (exp.length !== 1) out.push(`Expires must appear exactly once (found ${exp.length})`);
  else {
    const t = Date.parse(exp[0]);
    if (Number.isNaN(t)) out.push("Expires is not a date");
    else if (t <= now) out.push("expired");
    else if (t - now < 60 * DAY) out.push(`expires in ${Math.floor((t - now) / DAY)} days: renew it (set a date about six months on)`);
    else if (t - now > 366 * DAY) out.push("Expires is more than a year away (RFC 9116 advises less)");
  }
  if ((fields.canonical ?? []).join() !== CANONICAL) out.push(`Canonical must be ${CANONICAL}`);
  const policy = (fields.policy ?? [])[0] ?? "";
  if (policy !== "https://github.com/AINRA-organization/ainra/blob/main/SECURITY.md" || !existsSync(ROOT + "SECURITY.md")) out.push("Policy must point at this repository's SECURITY.md");
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (!existsSync(FILE)) { console.error("✗ site/.well-known/security.txt is missing"); process.exit(1); }
  const text = readFileSync(FILE, "utf8");
  if (process.argv.includes("--drill")) {
    const now = Date.now(), iso = (d) => new Date(now + d * DAY).toISOString();
    const withExpiry = (d) => text.replace(/^Expires:.*$/m, `Expires: ${iso(d)}`);
    const plants = [
      ["expired", withExpiry(-1), "expired"],
      ["expiring in a month", withExpiry(30), "renew it"],
      ["no Contact", text.replace(/^Contact:.*\n/gm, ""), "no Contact"],
      ["a Canonical for another host", text.replace(CANONICAL, "https://example.org/.well-known/security.txt"), "Canonical must be"],
    ];
    let bad = 0;
    for (const [what, planted, needle] of plants) {
      const p = problems(planted, now);
      if (p.some((x) => x.includes(needle))) console.log(`  ok    ${what} → refused: ${p.find((x) => x.includes(needle))}`);
      else { console.error(`  ✗     ${what} was not refused`); bad = 1; }
    }
    if (problems(withExpiry(180), now).length) { console.error("  ✗     a good file was refused: " + problems(withExpiry(180), now).join("; ")); bad = 1; }
    else console.log("  ok    a complete file good for six months → accepted");
    console.log(bad ? "SECURITY-TXT DRILL FAILED" : "SECURITY-TXT DRILL OK");
    process.exit(bad);
  }
  const p = problems(text);
  if (p.length) { for (const x of p) console.error("✗ security.txt: " + x); process.exit(1); }
  const days = Math.floor((Date.parse(/^Expires:\s*(.+)$/m.exec(text)[1]) - Date.now()) / DAY);
  console.log(`✓ security.txt: two contacts, canonical, policy; good for ${days} more days (this fails 60 days before it expires)`);
}
