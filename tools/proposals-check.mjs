#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make proposals-check — the register of AINRA Change Proposals is well formed (D-114, ACP-0001).
//
// It checks form, never merit: the people who keep the register are clerks, not judges. Each file in docs/proposals/
// named ACP-NNNN-*.md carries a header block with Number (matching its file name), Title, Kind (process, soft, hard,
// release), Status (Draft, Open, Accepted, Rejected, Withdrawn, Active), Created (YYYY-MM-DD), Author and Decision;
// numbers run from 0001 without gaps or repeats; an Accepted or Active proposal names its decision record (D-nnn), and
// that record exists in docs/DECISIONS.md; and docs/proposals/README.md lists every proposal with its status.
//
//   node tools/proposals-check.mjs             check the register
//   node tools/proposals-check.mjs --negative  plant each fault in a copy and show it is refused by name
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "docs/proposals");
const KINDS = new Set(["process", "soft", "hard", "release"]);
const STATUSES = new Set(["Draft", "Open", "Accepted", "Rejected", "Withdrawn", "Active"]);

export function check({ files, readme, decisions }) {
  const errors = [];
  const seen = [];
  for (const [name, text] of Object.entries(files)) {
    const m = name.match(/^ACP-(\d{4})-[a-z0-9-]+\.md$/);
    if (!m) { errors.push(`${name}: not named ACP-NNNN-short-name.md`); continue; }
    const field = (k) => (text.match(new RegExp(`^${k}:\\s*(.+)$`, "m")) || [])[1]?.trim();
    const number = field("Number"), status = field("Status"), kind = field("Kind"), created = field("Created");
    if (number !== `ACP-${m[1]}`) errors.push(`${name}: Number is ${number ?? "missing"}, the file says ACP-${m[1]}`);
    for (const k of ["Title", "Author", "Decision"]) if (!field(k)) errors.push(`${name}: no ${k}`);
    if (!KINDS.has(kind)) errors.push(`${name}: Kind ${kind ?? "missing"} is not one of ${[...KINDS].join(", ")}`);
    if (!STATUSES.has(status)) errors.push(`${name}: Status ${status ?? "missing"} is not one of ${[...STATUSES].join(", ")}`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(created ?? "")) errors.push(`${name}: Created is not YYYY-MM-DD`);
    if (status === "Accepted" || status === "Active") {
      const d = (field("Decision") ?? "").match(/D-\d{3}/);
      if (!d) errors.push(`${name}: ${status} without a decision record (Decision: D-nnn)`);
      else if (!decisions.includes(`## ${d[0]} `)) errors.push(`${name}: ${d[0]} is not in docs/DECISIONS.md`);
    }
    if (!readme.includes(`ACP-${m[1]}`) || !readme.includes(`| ${status} |`)) errors.push(`${name}: the README does not list it with its status`);
    seen.push(Number(m[1]));
  }
  seen.sort((a, b) => a - b);
  seen.forEach((n, i) => { if (n !== i + 1) errors.push(`numbers must run 0001, 0002, … without gaps or repeats (found ${String(n).padStart(4, "0")} at place ${i + 1})`); });
  return errors;
}

function real() {
  const files = {};
  for (const f of readdirSync(DIR)) if (f.startsWith("ACP-")) files[f] = readFileSync(join(DIR, f), "utf8");
  return { files, readme: readFileSync(join(DIR, "README.md"), "utf8"), decisions: readFileSync(join(ROOT, "docs/DECISIONS.md"), "utf8") };
}

const r = real();
if (process.argv.includes("--negative")) {
  const plant = (what, edit) => {
    const c = structuredClone(r); edit(c);
    const e = check(c);
    console.log(`  ${e.length ? "ok  caught" : "✗   MISSED"} ${what}${e.length ? ` — ${e[0]}` : ""}`);
    return e.length > 0;
  };
  const first = Object.keys(r.files).sort()[0];
  const results = [
    plant("a number that does not match its file", (c) => { c.files[first] = c.files[first].replace(/^Number:.*$/m, "Number:   ACP-0099"); }),
    plant("an unknown status", (c) => { c.files[first] = c.files[first].replace(/^Status:.*$/m, "Status:   Passed"); }),
    plant("an Active proposal with no decision", (c) => { c.files[first] = c.files[first].replace(/^Decision:.*$/m, "Decision: none"); }),
    plant("a gap in the numbers", (c) => { c.files["ACP-0009-gap.md"] = c.files[first].replace(/ACP-0001/g, "ACP-0009"); c.readme += "\n| ACP-0009 | x | process | Active |"; }),
    plant("a proposal the README does not list", (c) => { c.readme = c.readme.replace(/ACP-0002/g, "ACP-XXXX"); }),
  ];
  if (results.every(Boolean) && check(r).length === 0) { console.log("PROPOSALS-CHECK NEGATIVE OK — every planted fault refused, the real register left alone"); process.exit(0); }
  console.log("PROPOSALS-CHECK NEGATIVE FAILED"); process.exit(1);
}
const errors = check(r);
if (errors.length) { for (const e of errors) console.error(`  ✗ ${e}`); console.error("PROPOSALS-CHECK FAILED"); process.exit(1); }
console.log(`PROPOSALS-CHECK OK — ${Object.keys(r.files).length} proposal(s), numbered without gaps, each in the README with its status`);
