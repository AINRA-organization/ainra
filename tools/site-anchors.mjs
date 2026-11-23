// SPDX-License-Identifier: Apache-2.0 OR MIT
// Every verifier on the site states a registrar's WHOLE accreditation as its anchor (23 Nov 2026).
//
// A page that wrote `anchors: { [id]: { issuer_key, log_root_key } }` by hand dropped `chains_bound_from_leaf` (D-113)
// and the distrust cutoff (D-044/D-111). The pages that build their own presentation then never checked a bound
// chain's parties; the pages fed by a registrar's /present, which carries `chain_parties`, refused a valid bound
// passport as `schema_violation`. The fix is one helper per file, `anchorOf(accreditation)`, that copies every anchor
// field the directory states. This check holds it there:
//   node tools/site-anchors.mjs           exit 1 if a site script builds an anchor by naming `log_root_key` itself
//                                         outside `anchorOf`, or uses a registrar anchor without calling `anchorOf`
//   node tools/site-anchors.mjs --drill   the check, run on a planted copy of each mistake, must fail on both
import { readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const SITE = join(dirname(fileURLToPath(import.meta.url)), "..", "site");

function sources(root) {
  const out = [];
  for (const f of readdirSync(root)) if (f.endsWith(".html")) out.push(join(root, f));
  const js = join(root, "js");
  try { for (const f of readdirSync(js)) if (f.endsWith(".mjs") || f.endsWith(".js")) out.push(join(js, f)); } catch { /* no js dir */ }
  return out;
}

// What a mistake looks like, line by line: an anchor object written by hand (it names log_root_key outside the one
// helper), or an `anchors` value that never passes through anchorOf.
function problems(file, text) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    const at = `${file}:${i + 1}`;
    const helper = /const anchorOf\s*=/.test(line);
    if (!helper && /log_root_key\s*:/.test(line) && /issuer_key\s*:/.test(line)) out.push(`${at}: an anchor written by hand (use anchorOf(accreditation))`);
    if (/\banchors\s*[:=]\s*\{\s*\[/.test(line) && !/anchorOf\(/.test(line)) out.push(`${at}: a registrar anchor that does not go through anchorOf`);
  });
  return out;
}

function check(root) {
  const found = [];
  for (const f of sources(root)) found.push(...problems(f.slice(root.length + 1), readFileSync(f, "utf8")));
  return found;
}

if (process.argv.includes("--drill")) {
  const dir = mkdtempSync(join(tmpdir(), "site-anchors-"));
  const planted = {
    "by-hand.mjs": 'const v = run({ anchors: { [R.registrar]: { issuer_key: R.accreditation.issuer_key, log_root_key: R.accreditation.log_root_key } } });\n',
    "no-helper.mjs": "anchors = { [REGID]: acc };\n",
    "good.mjs": "const anchorOf = (a) => ({ issuer_key: a.issuer_key, log_root_key: a.log_root_key });\nanchors = { [REGID]: anchorOf(acc) };\n",
  };
  try {
    mkdirSync(join(dir, "js"));                                       // a fake site: the planted scripts sit where the walk looks
    for (const [n, body] of Object.entries(planted)) writeFileSync(join(dir, "js", n), body);
    const got = check(dir);
    const hand = got.some((p) => p.startsWith("js/by-hand.mjs")), helper = got.some((p) => p.startsWith("js/no-helper.mjs")), clean = !got.some((p) => p.startsWith("js/good.mjs"));
    console.log(`  ${hand ? "ok  " : "MISS"}  an anchor written by hand is refused`);
    console.log(`  ${helper ? "ok  " : "MISS"}  an anchor that skips anchorOf is refused`);
    console.log(`  ${clean ? "ok  " : "MISS"}  the helper itself is accepted`);
    if (!(hand && helper && clean)) { console.error("SITE-ANCHORS DRILL FAILED"); process.exit(1); }
    console.log("SITE-ANCHORS DRILL OK");
  } finally { rmSync(dir, { recursive: true, force: true }); }
} else {
  const found = check(SITE);
  if (found.length) { for (const p of found) console.error(`  ✗ site/${p}`); console.error(`site-anchors: ${found.length} problem(s)`); process.exit(1); }
  console.log("✓ site-anchors: every site verifier passes the registrar's whole accreditation (anchorOf)");
}
