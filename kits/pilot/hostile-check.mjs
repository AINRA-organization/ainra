#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make pilot-hostile — the pilot, in front of a service (no --watch), against requests it cannot read.
//
// A gate that stops is worse than no gate: the service behind it goes dark for everyone. Until 15 November 2026 the
// pilot's handler awaited everything with nothing around it, so one request with a Host no URL can hold, a
// Signature-Agent header that does not parse, or a body its sender abandoned ended the process (shipped since
// v0.5.0, found by the project's own review on 12 November). This sends each of those, and a body far larger than
// any presentation, to a real pilot in both modes, and after every one asks it something ordinary.
//
// Hermetic: the directory and roots are the committed sample artifacts, and the "registrar" is a server in this
// file that serves an empty link index. Nothing here is ever admitted, so the upstream must see no request at all:
// a request the pilot cannot read is refused, never passed on.
//
// WITNESS: could this fail? Yes — run against the pilot as it was before this change (15 November 2026) it reports
// the process gone: in link mode at the first case, the Host no URL can hold; in passport mode at the abandoned
// body. The upstream's request count is the second witness: a guard that "survived" by forwarding what it could not
// read would raise it. The body limit is its own case and must answer 413, not merely something that is not 2xx.
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = fileURLToPath(new URL("./", import.meta.url));
const SAMPLES = fileURLToPath(new URL("../verifier/sample-artifacts/", import.meta.url));
const PILOT_JS = HERE + "pilot.mjs";
let bad = 0;
const ok = (m) => console.log(`  ok    ${m}`);
const fail = (m) => { console.error(`  ✗     ${m}`); bad = 1; };
const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let upstreamSeen = 0;
const upstream = http.createServer((req, res) => { upstreamSeen++; res.end("upstream"); });
const upPort = await listen(upstream);
// A registrar with nothing linked: an index and a status publication no gate will accept anything from.
const registrar = http.createServer((req, res) => { res.setHeader("content-type", "application/json"); res.end(req.url.startsWith("/links") ? '{"links":[]}' : "{}"); });
const regPort = await listen(registrar);

// One raw exchange: write `text` (and optionally stop half-way), then read whatever comes back until the pilot
// closes or `ms` passes. Raw, because a well-behaved client cannot send these.
function raw(port, text, { hangUpAfter = null, ms = 1500 } = {}) {
  return new Promise((resolve) => {
    const s = net.connect(port, "127.0.0.1");
    let got = "";
    const done = () => { s.destroy(); resolve(got); };
    s.on("connect", () => { s.write(text); if (hangUpAfter !== null) setTimeout(() => s.destroy(), hangUpAfter); });
    s.on("data", (d) => { got += d.toString("latin1"); });
    s.on("close", () => resolve(got)); s.on("error", () => resolve(got));
    setTimeout(done, ms);
  });
}
const statusOf = (answer) => Number(/^HTTP\/1\.1 (\d{3})/.exec(answer)?.[1] ?? 0);

async function battery(mode, extra) {
  console.log(`\n${mode} mode`);
  const port = 20000 + Math.floor(Math.random() * 20000);
  const p = spawn("node", [PILOT_JS, "--upstream", `http://127.0.0.1:${upPort}`, "--listen", `127.0.0.1:${port}`,
    "--directory", SAMPLES + "directory.json", "--roots", SAMPLES + "roots.json", "--mode", mode, "--max-body", "1048576", ...extra], { stdio: ["ignore", "ignore", "pipe"] });
  let gone = null, stderr = "";
  p.stderr.on("data", (d) => { stderr += d; });
  p.on("exit", (code, sig) => { gone = `exit ${code ?? sig}`; });
  const alive = async () => {
    if (gone) return false;
    try { const r = await fetch(`http://127.0.0.1:${port}/ordinary`, { signal: AbortSignal.timeout(3000) }); await r.arrayBuffer(); return r.status === 403 || r.status === 428 || r.status === 401; }
    catch { return false; }
  };
  for (let i = 0; i < 100 && !(await alive()); i++) await sleep(100);
  if (!(await alive())) { fail(`the pilot did not start (${gone ?? "no answer"}) ${stderr.split("\n")[0]}`); p.kill(); return; }
  ok("an ordinary unsigned request is refused, and the pilot answers");

  const big = "x".repeat(4 << 20);
  const cases = [
    ["a Host no URL can hold, beside a signature-agent header", `GET / HTTP/1.1\r\nHost: a b\r\nSignature-Agent: "https://agent.example"\r\nConnection: close\r\n\r\n`, {}],
    ["a Signature-Agent header that does not parse", `GET / HTTP/1.1\r\nHost: x.example\r\nSignature-Agent: "unterminated\r\nSignature-Input: sig=("@authority");keyid="k"\r\nSignature: sig=:AAAA:\r\nConnection: close\r\n\r\n`, {}],
    ["a body its sender abandons half-way", `POST /orders HTTP/1.1\r\nHost: x.example\r\nContent-Length: 100000\r\n\r\nonly-this-much`, { hangUpAfter: 150 }],
    ["a four-megabyte body against --max-body 1048576", `POST /orders HTTP/1.1\r\nHost: x.example\r\nContent-Length: ${big.length}\r\nConnection: close\r\n\r\n${big}`, { ms: 4000, want: 413 }],
    ["a request target that is not a path", `GET http://[::bad/ HTTP/1.1\r\nHost: x.example\r\nSignature-Agent: "https://agent.example"\r\nConnection: close\r\n\r\n`, {}],
    ...(mode === "passport" ? [["a presentation that is not JSON, sent to be stored", `POST /.well-known/ainra-presentation HTTP/1.1\r\nHost: x.example\r\nContent-Type: application/json\r\nContent-Length: 9\r\nConnection: close\r\n\r\n{"claims"`, {}]] : []),
  ];
  for (const [what, text, opts] of cases) {
    const before = upstreamSeen;
    const answer = await raw(port, text, opts);
    await sleep(150);
    const up = await alive();
    const s = statusOf(answer);
    if (!up) { fail(`${what} → the pilot is gone (${gone ?? "no answer"})`); break; }
    if (upstreamSeen !== before) { fail(`${what} → it reached the upstream`); continue; }
    if (s >= 200 && s < 300) { fail(`${what} → answered ${s}`); continue; }
    if (opts.want && s !== opts.want) { fail(`${what} → answered ${s || "nothing"}, wanted ${opts.want}`); continue; }
    ok(`${what} → ${s ? "refused " + s : "connection closed"}; the pilot still answers; nothing reached the upstream`);
  }
  p.kill();
}

await battery("link", ["--registrar", `http://127.0.0.1:${regPort}`, "--freshness", "F1"]);
await battery("passport", ["--audience", "https://x.example", "--freshness", "F3"]);
upstream.close(); registrar.close();
console.log(bad ? "\nPILOT-HOSTILE FAILED" : "\nPILOT-HOSTILE OK: requests the pilot cannot read are refused, never forwarded, and it keeps answering — both modes");
process.exit(bad);
