#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make crossed-withdrawal — two issuers, one verifier, and the verifier cut off from both.
//
// The question a platform asks before it relies on someone else's agent: "if the issuer withdraws that agent, do I
// refuse it, without an account at the issuer, without their API, without even a network path to them?" This runs it:
//
//   · two registrars, each with its own keys and its own log, accredited in one directory under one TEST root;
//   · one agent from each, holding the bundle its own registrar gave it;
//   · a mirror: plain files (tools/publish-static.mjs) carried by a courier that neither issuer controls;
//   · one verifier, in a process the kernel gives NO network (a new network namespace: no interface, every connect
//     fails). It holds the directory, the two root keys, the bundles the agents presented and the mirror's files.
//     It has one rule for both issuers, and it signs a decision record for every answer.
//
//   round 1   both agents present                         → both allowed, under the one rule
//   withdraw  issuer A revokes its agent; the courier runs
//   round 2   both agents present again, unchanged        → A refused: revoked · B still allowed
//   round 3   the courier never came (the old files)      → A is still allowed until the status is older than the
//                                                           verifier's class, then both are refused: stale_status.
//                                                           That window is the cost of checking offline, and it is
//                                                           printed for all three classes.
//   controls  a mirror that changes one bit; a mirror that hands issuer B's list for issuer A's agent → refused
//
// Everything is on loopback and under a TEST root made for this run from the public fixed seed. It proves the
// mechanism. It is not evidence that two organisations run it, and no outside registrar can be accredited on the
// published test network yet (docs/quickstarts/registrar.md).
//
// The egress cut is the kernel's (`unshare --user --net`), and the verifier proves it on itself each round: it lists
// its interfaces (none) and tries to connect to each issuer (the kernel answers ENETUNREACH). Where unprivileged
// namespaces are switched off, the run says so and falls back to a verifier that refuses, and logs, any connection it
// is asked to make: weaker, and labelled as such in the output.
//
// WITNESS: could this fail? Yes, three ways it is built to. (1) Round 2 with the pre-withdrawal files is round 3:
// there A is ALLOWED, so "refused" in round 2 cannot come from a verifier that refuses everything. (2) B must stay
// allowed in round 2, so "refused" cannot come from a verifier that lost its trust. (3) `--witness-open` runs the
// verifier WITHOUT the namespace: its self-test must then reach the issuer, and the run reports the cut as absent —
// so "no egress" in the normal run is observed, not assumed.
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, readFileSync, writeFileSync, appendFileSync, existsSync, cpSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { createHash, randomBytes } from "node:crypto";
import net from "node:net";
import os from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Verifier, createDecisionLog, verifyDecisionChain, decisionRequestDigest } from "../packages/sdk-ts/dist/index.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const CLASSES = { F1: 30, F2: 300, F3: 86_400 };
const argv = process.argv.slice(2);
const opt = (k, d) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const j = (p) => JSON.parse(readFileSync(p, "utf8"));

// ══ the verifier ══════════════════════════════════════════════════════════════════════════════════════════════════
// One invocation is one round. It reads only files under <dir>; it is told the issuers' addresses for one purpose:
// to try them, and record that it could not.
if (argv[0] === "--verifier") {
  const dir = argv[1], round = opt("round", "?"), mirror = join(dir, opt("mirror", "mirror")), nowArg = Number(opt("now"));
  const now = Number.isFinite(nowArg) ? nowArg : Math.floor(Date.now() / 1000);
  const cls = opt("class", "F2");
  const sdkRequire = createRequire(new URL("../packages/sdk-ts/package.json", import.meta.url));
  const { ed25519 } = await import(pathToFileURL(sdkRequire.resolve("@noble/curves/ed25519")).href);

  // (1) the cut, observed from inside
  const ifaces = Object.keys(os.networkInterfaces());
  const tryConnect = (addr) => new Promise((res) => {
    const [host, port] = addr.split(":");
    const s = net.connect(Number(port), host);
    const done = (r) => { s.destroy(); res(r); };
    s.setTimeout(1500, () => done("timeout"));
    s.on("connect", () => done("CONNECTED"));
    s.on("error", (e) => done(e.code ?? "error"));
  });
  const issuers = j(join(dir, "issuers.json"));
  const egress = [];
  // Tried only where the answer is evidence: inside the namespace, or in the witness. On the host's network a
  // verifier that "tests" the issuers would be making the very connections it claims not to make.
  if (argv.includes("--probe")) for (const [id, addr] of Object.entries(issuers)) egress.push({ id, addr, result: await tryConnect(addr) });
  const cut = ifaces.length === 0 && egress.length > 0 && egress.every((e) => e.result !== "CONNECTED");
  appendFileSync(join(dir, "egress.log"), JSON.stringify({ at: new Date().toISOString(), round, pid: process.pid, interfaces: ifaces, attempts: egress, cut }) + "\n");

  // (2) trust: the directory under the two root keys, and nothing else
  const roots = j(join(dir, "trust/roots.json"));
  const verifier = Verifier.fromDirectoryB64(j(join(dir, "trust/directory.json")), roots.root_ed25519, roots.root_slh, cls);
  if (!verifier) { console.log(JSON.stringify({ error: "directory not authentic" })); process.exit(1); }

  // (3) status: whatever the courier left, one file for the whole network. Each registrar's text is checked under
  // that registrar's own key by verify(); this file is trusted for nothing.
  const network = j(join(mirror, "network-status.json")).registrars;
  const statusOf = (registrar, from = registrar) => {
    const text = network[from]?.["status-list.json"];
    return typeof text === "string" ? JSON.parse(text) : null;
  };
  const withStatus = (bundle, pub) => ({
    ...bundle, status_list: pub.status_list_b64, status_len: pub.bit_len, status_issued_at: pub.issued_at,
    status_uri: pub.uri, status_sig_ed25519: pub.sig_ed25519, status_sig_mldsa65: pub.sig_mldsa65,
    fresh_head: undefined, status_delegate_cert: undefined,
  });

  // (4) the decision log: this verifier's own key, one signed and chained line per answer
  const keyFile = join(dir, "verifier.key"), logFile = join(dir, "decisions.jsonl");
  if (!existsSync(keyFile)) writeFileSync(keyFile, Buffer.from(randomBytes(32)).toString("base64url") + "\n", { mode: 0o600 });
  const secret = Buffer.from(readFileSync(keyFile, "utf8").trim(), "base64url");
  const gatePublic = ed25519.getPublicKey(secret);
  const lastLine = existsSync(logFile) ? (readFileSync(logFile, "utf8").trim().split("\n").filter(Boolean).pop() ?? "") : "";
  const log = createDecisionLog({ gatePublic, sign: (m) => ed25519.sign(m, secret), append: (l) => appendFileSync(logFile, l + "\n"), freshness: cls, lastLine });
  writeFileSync(join(dir, "verifier.pub"), Buffer.from(gatePublic).toString("base64url") + "\n");
  const digest = (t) => createHash("sha256").update(t).digest("base64url");

  // (5) THE ONE RULE, for every issuer: the passport verifies under this directory with status inside this class.
  const answers = [];
  const plan = opt("plan") ? JSON.parse(opt("plan")) : readdirSync(join(dir, "agents")).sort().map((f) => ({ agent: f.replace(/\.json$/, "") }));
  for (const p of plan) {
    const bundle = j(join(dir, "agents", `${p.agent}.json`));
    const { registrar, sub, ...presented } = bundle;                       // the two labels the run added; the rest is what the agent presented
    let pub = statusOf(registrar, p.statusFrom ?? registrar);
    if (pub && p.flipBit) { const b = Buffer.from(pub.status_list_b64, "base64url"); b[b.length - 1] ^= 1; pub = { ...pub, status_list_b64: b.toString("base64url") }; }
    let verdict;
    try { verdict = pub ? verifier.verify(withStatus(presented, pub), now) : { verdict: "invalid", reason: "stale_status" }; }
    catch { verdict = { verdict: "invalid", reason: "schema_violation" }; }
    if (!p.control) log.record({
      at: now, kind: "passport", subject: sub,
      ...(verdict.verdict === "valid" ? { operator: sub.split(":")[2] } : { reason: verdict.reason }),
      verdict: verdict.verdict,
      request: decisionRequestDigest({ method: "POST", authority: "verifier.test", path: "/act" }),
      ...(pub ? { status: { uri: pub.uri, issued_at: pub.issued_at, list: digest(pub.status_list_b64) } } : {}),
      ...(bundle.checkpoint ? { checkpoint: { origin: bundle.checkpoint.origin, size: bundle.checkpoint.size, root: bundle.checkpoint.root } } : {}),
    });
    answers.push({ agent: p.agent, registrar, sub, ...verdict, status_issued_at: pub?.issued_at ?? null, status_age: pub ? now - pub.issued_at : null, control: p.control ?? null });
  }
  console.log(JSON.stringify({ round, class: cls, now, cut, interfaces: ifaces, egress, answers }));
  process.exit(0);
}

// ══ the run ═══════════════════════════════════════════════════════════════════════════════════════════════════════
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
const step = (m) => console.log(`\n${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => res(p)); }); });
const BOX = ROOT + "target/release/registrar-box", ACCREDIT = ROOT + "target/release/accredit";
for (const b of [BOX, ACCREDIT]) if (!existsSync(b)) { console.error(`crossed-withdrawal: ${b} is not built — run it through \`make crossed-withdrawal\``); process.exit(2); }

const keep = opt("keep");
const dir = keep ?? mkdtempSync(join(os.tmpdir(), "ainra-crossed-"));
for (const d of ["trust", "agents", "mirror", "mirror-old", "issuer-a", "issuer-b"]) mkdirSync(join(dir, d), { recursive: true });
const children = [];
const cleanup = () => { for (const c of children) try { process.kill(-c.pid); } catch { try { c.kill(); } catch { /* gone */ } } if (!keep) rmSync(dir, { recursive: true, force: true }); };
process.on("exit", cleanup); process.on("SIGINT", () => process.exit(130)); process.on("SIGTERM", () => process.exit(143));

async function http(url, init) {
  const r = await fetch(url, init); const t = await r.text();
  let body; try { body = JSON.parse(t); } catch { body = t; }
  return { status: r.status, body };
}

// ── the two issuers ───────────────────────────────────────────────────────────────────────────────────────────────
step("1 · two issuers, each with its own keys and its own log");
const ISSUERS = [{ key: "issuer-a", id: "registrar-31" }, { key: "issuer-b", id: "registrar-32" }];
for (const is of ISSUERS) {
  is.port = await freePort(); is.addr = `127.0.0.1:${is.port}`; is.url = `http://${is.addr}`;
  is.token = randomBytes(24).toString("hex");                       // held in memory, sent only in a header, never printed
  const p = spawn(BOX, [is.addr, is.id, join(dir, is.key, "data")], {
    env: { ...process.env, AINRA_STAGE: "1", AINRA_CLOCK: "wall", AINRA_STAGE_ISSUE_TOKEN: is.token },
    stdio: ["ignore", "ignore", "ignore"], detached: true,
  });
  children.push(p);
  let up = false;
  for (let i = 0; i < 80 && !up; i++) { try { up = (await fetch(`${is.url}/accreditation`, { signal: AbortSignal.timeout(500) })).ok; } catch { await sleep(150); } }
  if (!up) { fail(`${is.id} did not start`); process.exit(1); }
  const acc = await http(`${is.url}/accreditation`);
  writeFileSync(join(dir, is.key, "accreditation.json"), JSON.stringify(acc.body));
  ok(`${is.id} up on ${is.addr}`);
}
const keysDiffer = JSON.stringify(j(join(dir, "issuer-a/accreditation.json")).issuer_key) !== JSON.stringify(j(join(dir, "issuer-b/accreditation.json")).issuer_key);
keysDiffer ? ok("their issuer keys differ") : fail("the two issuers hold the same key");

step("2 · one directory under one TEST root accredits both");
{
  const env = { ...process.env }; delete env.AINRA_ROOT_SEED_FILE; delete env.AINRA_DIRECTORY_EPOCH;
  execFileSync(ACCREDIT, [join(dir, "trust"), join(dir, "issuer-a/accreditation.json"), join(dir, "issuer-b/accreditation.json")], { env, stdio: "ignore" });
  const d = j(join(dir, "trust/directory.json"));
  d.entries?.length === 2 ? ok(`directory epoch ${d.epoch}: ${d.entries.map((e) => e.registrar).join(", ")} · TEST root, made for this run`) : fail("the directory does not list both issuers");
}
writeFileSync(join(dir, "issuers.json"), JSON.stringify(Object.fromEntries(ISSUERS.map((i) => [i.id, i.addr]))));

step("3 · each issuer issues one passport; each agent keeps the bundle its own issuer gave it");
const now = () => Math.floor(Date.now() / 1000);
for (const is of ISSUERS) {
  const issued = await http(`${is.url}/demo/issue`, { method: "POST", body: JSON.stringify({ operator: "specimen", lineage: is.key === "issuer-a" ? "browser-a" : "browser-b" }) });
  if (issued.status !== 200) { fail(`${is.id}: issue failed (${issued.status})`); process.exit(1); }
  is.sub = issued.body.sub;
  const bundle = await http(`${is.url}/present?sub=${encodeURIComponent(is.sub)}&now=${now()}`);
  if (bundle.status !== 200) { fail(`${is.id}: present failed (${bundle.status})`); process.exit(1); }
  writeFileSync(join(dir, "agents", `${is.key}.json`), JSON.stringify({ ...bundle.body, sub: is.sub, registrar: is.id }));
  ok(`${is.sub}`);
}

// ── the courier: plain files, from both issuers, to a place neither of them runs ─────────────────────────────────
function courier(out) {
  const r = spawnSync("node", [ROOT + "tools/publish-static.mjs", "--out", join(dir, out), ...ISSUERS.flatMap((i) => ["--registrar", i.url])], { encoding: "utf8" });
  if (r.status !== 0) { fail(`the courier could not copy the issuers' files: ${(r.stderr || r.stdout).trim().split("\n").pop()}`); process.exit(1); }
  return Object.fromEntries(Object.entries(j(join(dir, out, "network-status.json")).registrars).map(([id, v]) => [id, JSON.parse(v["status-list.json"]).issued_at]));
}

// ── the verifier, in a process with no network ───────────────────────────────────────────────────────────────────
const OPEN = argv.includes("--witness-open");
// AINRA_CROSSED_NO_NAMESPACE=1 forces the fallback, so that path can be exercised on a machine that has namespaces.
const nsWorks = !OPEN && process.env.AINRA_CROSSED_NO_NAMESPACE !== "1" && spawnSync("unshare", ["--user", "--net", "true"], { stdio: "ignore" }).status === 0;
function verify(round, extra = []) {
  const args = [SELF, "--verifier", dir, "--round", round, ...(nsWorks || OPEN ? ["--probe"] : []), ...extra];
  const r = nsWorks ? spawnSync("unshare", ["--user", "--net", "--map-root-user", "node", ...args], { encoding: "utf8" }) : spawnSync("node", args, { encoding: "utf8" });
  if (r.status !== 0) { fail(`verifier, ${round}: ${(r.stderr || r.stdout).trim().split("\n").pop()}`); process.exit(1); }
  return JSON.parse(r.stdout.trim().split("\n").pop());
}
const answer = (res, agent) => res.answers.find((a) => a.agent === agent);
const show = (a) => a.verdict === "valid" ? "allowed" : `refused: ${a.reason}`;

step("4 · the courier carries both issuers' signed status to the mirror; the verifier is cut off");
const t0 = courier("mirror");
cpSync(join(dir, "mirror"), join(dir, "mirror-old"), { recursive: true });       // what the mirror held BEFORE the withdrawal
const r1 = verify("round 1 · both present");
if (OPEN) {
  !r1.cut && r1.egress.some((e) => e.result === "CONNECTED")
    ? ok("WITNESS: without the namespace the verifier's own test REACHES an issuer, and reports the cut as absent")
    : fail("WITNESS: the verifier claims a cut although it runs with the host's network");
  console.log(bad ? "\nCROSSED-WITHDRAWAL WITNESS FAILED" : "\nCROSSED-WITHDRAWAL WITNESS OK: the egress test can see an open network");
  process.exit(bad);
}
if (nsWorks) {
  r1.cut ? ok(`kernel cut: the verifier sees ${r1.interfaces.length} network interfaces; connecting to ${r1.egress.map((e) => `${e.id} → ${e.result}`).join(", ")}`)
         : fail(`the verifier still has a network: interfaces ${JSON.stringify(r1.interfaces)}, ${JSON.stringify(r1.egress)}`);
} else {
  console.log("  note  unprivileged network namespaces are not available here: the verifier ran on the host's network and");
  console.log("        only RECORDED that it made no connection of its own. Weaker than a kernel cut; run on Linux with user namespaces for the real one.");
}

step("5 · round 1: one rule, two issuers");
for (const is of ISSUERS) { const a = answer(r1, is.key); a.verdict === "valid" ? ok(`${is.id}'s agent → allowed (status ${a.status_age}s old, class ${r1.class})`) : fail(`${is.id}'s agent → ${show(a)}`); }

step("6 · issuer A withdraws its agent; the courier runs again");
const A = ISSUERS[0], B = ISSUERS[1];
await sleep(1100);                                                              // a later second, so the new list is newer
const tRevoke = Date.now();
const rv = await http(`${A.url}/demo/revoke`, { method: "POST", body: JSON.stringify({ sub: A.sub, now: now() }) });
rv.status === 200 ? ok(`${A.id} revoked ${A.sub}`) : fail(`revoke failed: ${rv.status} ${JSON.stringify(rv.body)}`);
const t1 = courier("mirror");
t1[A.id] > t0[A.id] ? ok(`the mirror now holds ${A.id}'s list signed at ${t1[A.id]} (was ${t0[A.id]})`) : fail("the mirror's copy of the withdrawing issuer's list did not change");

step("7 · round 2: the same two agents, the same bundles, the verifier still cut off");
const r2 = verify("round 2 · after withdrawal");
const tRefused = Date.now();
{
  const a = answer(r2, A.key), b = answer(r2, B.key);
  a.verdict === "invalid" && a.reason === "revoked" ? ok(`${A.id}'s agent → refused: revoked`) : fail(`${A.id}'s agent → ${show(a)} (wanted refused: revoked)`);
  b.verdict === "valid" ? ok(`${B.id}'s agent → still allowed`) : fail(`${B.id}'s agent → ${show(b)} (wanted allowed)`);
  if (nsWorks && !r2.cut) fail("the verifier had a network in round 2");
  ok(`from the issuer's revoke to this verifier's refusal: ${((tRefused - tRevoke) / 1000).toFixed(1)} s here; in a deployment it is however often the mirror is refreshed`);
}

step("8 · round 3: the courier never came (the files from before the withdrawal)");
const signedAt = t0[A.id];
const exposure = {};
for (const [cls, window] of Object.entries(CLASSES)) {
  const inside = verify(`round 3 · ${cls} · old files, ${window}s old`, ["--mirror", "mirror-old", "--class", cls, "--now", String(signedAt + window), "--plan", JSON.stringify([{ agent: A.key, control: "stale-mirror" }, { agent: B.key, control: "stale-mirror" }])]);
  const past = verify(`round 3 · ${cls} · old files, ${window + 1}s old`, ["--mirror", "mirror-old", "--class", cls, "--now", String(signedAt + window + 1), "--plan", JSON.stringify([{ agent: A.key, control: "stale-mirror" }, { agent: B.key, control: "stale-mirror" }])]);
  const ai = answer(inside, A.key), ap = answer(past, A.key), bp = answer(past, B.key);
  exposure[cls] = window;
  ai.verdict === "valid" && ap.reason === "stale_status" && bp.reason === "stale_status"
    ? ok(`${cls}: with files ${window}s old the withdrawn agent is STILL allowed; at ${window + 1}s both are refused: stale_status`)
    : fail(`${cls}: at ${window}s A is ${show(ai)}, at ${window + 1}s A is ${show(ap)} and B is ${show(bp)}`);
}
console.log(`  so    a verifier that cannot be reached by the courier keeps a withdrawn agent for at most its class: F1 ${CLASSES.F1}s, F2 ${CLASSES.F2}s, F3 ${CLASSES.F3}s — and then refuses everyone. The verifier chooses the class.`);

step("9 · controls: what a mirror cannot do");
{
  const c = verify("controls", ["--plan", JSON.stringify([{ agent: B.key, flipBit: true, control: "one bit changed" }, { agent: A.key, statusFrom: B.id, control: "another issuer's list" }])]);
  const flipped = c.answers[0], swapped = c.answers[1];
  flipped.verdict === "invalid" ? ok(`one bit changed in ${B.id}'s list → refused: ${flipped.reason}`) : fail("a mirror changed a status bit and the verifier accepted it");
  swapped.verdict === "invalid" ? ok(`${B.id}'s list handed over for ${A.id}'s agent → refused: ${swapped.reason}`) : fail("a mirror answered for the wrong issuer and the verifier accepted it");
}

step("10 · the record: every answer of rounds 1 and 2, signed and chained by the verifier");
{
  const lines = readFileSync(join(dir, "decisions.jsonl"), "utf8").trim().split("\n");
  const pub = Buffer.from(readFileSync(join(dir, "verifier.pub"), "utf8").trim(), "base64url");
  const chain = verifyDecisionChain(lines, new Uint8Array(pub));
  chain.ok && chain.count === 4 ? ok(`${chain.count} decision records verify under the verifier's key, in order`) : fail(`decision chain: ${JSON.stringify(chain)}`);
  const cutLine = lines.slice(0, -1); cutLine[1] = cutLine[1].replace('"verdict":"valid"', '"verdict":"invalid"');
  !verifyDecisionChain(cutLine, new Uint8Array(pub)).ok ? ok("an edited record is found") : fail("an edited decision record passed");
  for (const l of lines) { const r = JSON.parse(l); console.log(`        #${r.seq} ${r.subject} → ${r.verdict}${r.reason ? " (" + r.reason + ")" : ""} · status signed ${r.status?.issued_at}`); }
  const eg = readFileSync(join(dir, "egress.log"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const reached = eg.reduce((n, e) => n + e.attempts.filter((a) => a.result === "CONNECTED").length, 0);
  nsWorks ? ok(`egress log: ${eg.length} verifier runs, ${eg.filter((e) => e.cut).length} with the kernel cut observed, ${reached} connections to an issuer`)
          : console.log(`  note  egress log: ${eg.length} verifier runs on the host's network, none of which was given a connection to make`);
  if (reached) fail("a verifier run reached an issuer");
  if (nsWorks && eg.some((e) => !e.cut)) fail("a verifier run had a network");
}
if (keep) console.log(`\n  kept  ${dir}  (decisions.jsonl, verifier.pub, egress.log, mirror/, trust/)`);

console.log(bad ? "\nCROSSED-WITHDRAWAL FAILED"
  : `\nCROSSED-WITHDRAWAL OK: two issuers under one TEST root, one verifier with ${nsWorks ? "no network" : "no connection of its own"}; issuer A's withdrawal refused its agent and left issuer B's allowed`);
process.exit(bad);
