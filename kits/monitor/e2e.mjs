#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make monitor-e2e — a registrar's log watched for issuance nobody expected, live (PLAN-M53 step 11, D-116).
//
// Against the live registrar (`make live-up`), with `ainra monitor`:
//   1. an operator's one expected passport: nothing to report
//   2. a second passport in the operator's name that is not on its list: named, exit 3
//   3. a feed that hides one entry: the entries no longer rebuild the signed root, exit 3
//   4. a log smaller than the monitor saw last: ROLLBACK, exit 3
//   5. a log whose history differs from what the monitor saw: FORK, exit 3
//   6. once the operator owns the stray passport, the next run resumes from the kept compact range (D-119)
//
// TEST-ROOT, loopback. WITNESS: step 1 is the positive control (exit 0); steps 2 to 5 must each raise their own alarm
// by name. If any of them passes quietly, this drill fails.
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = new URL("../../", import.meta.url).pathname;
const REG = process.env.AINRA_REGISTRAR ?? "http://127.0.0.1:4970";
const NET = process.env.AINRA_LIVE_PUBLIC ?? join(ROOT, "live/public");
const BIN = join(ROOT, "target/release/ainra");
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
const step = (m) => console.log(`\n${m}`);

try { await fetch(`${REG}/accreditation`, { signal: AbortSignal.timeout(3000) }); }
catch { console.error(`monitor-e2e: no live registrar at ${REG} — run \`make live-up\` first`); process.exit(2); }
let TOKEN;
try { TOKEN = readFileSync(join(ROOT, "live/.issue-token"), "utf8").trim(); }
catch { console.error("monitor-e2e: live/.issue-token missing — start the registrar with `make live-up`"); process.exit(2); }

const dir = mkdtempSync(join(tmpdir(), "ainra-monitor-"));
const op = `mon-${process.pid}`;
async function issue(lineage) {
  for (let i = 0; i < 18; i++) {
    const r = await fetch(`${REG}/issue`, {
      method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ operator: op, lineage, version: "1.0.0", tier: "L1", auth_class: "A2", principal_proof: "deadbeefmonitor",
        capabilities: ["read:x"], scope_ceiling: ["read:x"], hops: [] }),
    });
    const b = await r.json().catch(() => ({}));
    if (r.status === 200 && b.sub) return b.sub;
    if (r.status !== 429) throw new Error(`issue ${lineage}: ${r.status} ${JSON.stringify(b)}`);
    await new Promise((res) => setTimeout(res, 5000)); // the registrar allows 30 writes a minute
  }
  throw new Error(`issue ${lineage}: still rate limited`);
}
// Asynchronous on purpose: step 3's proxy runs in this process and must keep answering while the monitor runs.
function monitor(reg, state = "state.json") {
  return new Promise((resolve) => {
    const c = spawn(BIN, ["monitor", "--registrar", reg, "--net", NET, "--roots", join(NET, "roots.json"), "--watch", op,
      "--expect", join(dir, "expect.txt"), "--state", join(dir, state)]);
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    c.on("close", (code) => resolve({ code, out }));
  });
}

step(`1 · operator ${op}: one passport, on its list`);
const expected = await issue("assistant");
writeFileSync(join(dir, "expect.txt"), `${expected}\n`);
let m = await monitor(REG);
m.code === 0 && /every one on its list/.test(m.out) ? ok(`nothing to report: ${expected}`) : fail(`expected exit 0: ${m.code}\n${m.out}`);
const seen = JSON.parse(readFileSync(join(dir, "state.json"), "utf8"));

step("2 · a passport in the operator's name that it never asked for");
const stray = await issue("shadow");
m = await monitor(REG);
m.code === 3 && m.out.includes(`UNEXPECTED ISSUANCE: ${stray}`) ? ok(`named: ${stray}`) : fail(`expected the stray passport named: ${m.code}\n${m.out}`);

step("3 · a feed that hides one entry");
const proxy = createServer(async (req, res) => {
  const up = await fetch(`${REG}${req.url}`);
  let body = await up.text();
  if (req.url.startsWith("/log/entries")) {
    const page = JSON.parse(body);
    if (page.entries.length > 1) page.entries.splice(1, 1);
    body = JSON.stringify(page);
  }
  res.writeHead(up.status, { "content-type": "application/json" }).end(body);
});
await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
const via = `http://127.0.0.1:${proxy.address().port}`;
m = await monitor(via, "state-proxy.json");
m.code === 3 && /do not rebuild the signed root/.test(m.out) ? ok("refused: the entries no longer rebuild the signed root") : fail(`expected a rebuild alarm: ${m.code}\n${m.out}`);
proxy.close();

step("4 · a log smaller than the monitor saw last");
writeFileSync(join(dir, "state-big.json"), JSON.stringify({ ...seen, size: seen.size + 1000 }));
m = await monitor(REG, "state-big.json");
m.code === 3 && /ROLLBACK/.test(m.out) ? ok("ROLLBACK raised") : fail(`expected ROLLBACK: ${m.code}\n${m.out}`);

step("5 · a history different from the one the monitor saw");
writeFileSync(join(dir, "state-fork.json"), JSON.stringify({ ...seen, root: Buffer.alloc(32, 7).toString("base64url") }));
m = await monitor(REG, "state-fork.json");
m.code === 3 && /FORK/.test(m.out) ? ok("FORK raised") : fail(`expected FORK: ${m.code}\n${m.out}`);

step("6 · the next run reads only what the log added (D-119)");
writeFileSync(join(dir, "expect.txt"), `${expected}\n${stray}\n`); // the operator now owns the second passport
m = await monitor(REG);
const kept = JSON.parse(readFileSync(join(dir, "state.json"), "utf8"));
m.code === 0 && /new entr(y|ies) since size \d+ rebuild the signed root from the \d+ hash\(es\) kept/.test(m.out)
  && Array.isArray(kept.frontier) && kept.frontier.length <= 64
  ? ok(`resumed after ${seen.size} checked entries, kept ${kept.frontier.length} hash(es), read only the new ones`)
  : fail(`expected a resumed run: ${m.code}\n${m.out}`);

rmSync(dir, { recursive: true, force: true });
console.log(bad ? "\nMONITOR E2E FAILED" : "\nMONITOR E2E OK: an unexpected passport named, a hidden entry, a rollback and a fork each caught, and a run resumed from the kept range — live");
process.exit(bad);
