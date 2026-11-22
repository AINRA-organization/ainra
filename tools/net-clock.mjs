// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The clock a network states in its published record.
//
// A network's record says which clock it keeps: index.json carries `"clock": "wall"` when its registrars keep real
// time (tools/stage.sh publish writes it). No such field, or `"pinned"`, is the pinned clock: every signature in the
// record is made at one fixed instant, and that instant is the record's own `generated_window.verified_at`.
// Everything that reads or drives a network asks here, so nobody has to remember which clock a network is on.
//
//   node tools/net-clock.mjs <record>     <record> is a URL or a folder holding index.json
//       prints  wall                      read it at the real clock, and name no time in a request
//       prints  pinned <unix seconds>     read it at that instant, and name it in requests
//       exit 2, one line on stderr        the record could not be read: no record, no answer
//
// The statement is not signed. It chooses how a tool READS a record; it proves nothing about the record. A reader
// that must not be fooled about time (`ainra ctl status`) uses its own clock and takes no word for it.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

/** `{ clock: "wall" | "pinned", at: number | null }` from a parsed index.json. `at` is the pinned instant. */
export function clockOf(index) {
  if (index?.clock === "wall") return { clock: "wall", at: null };
  if (index?.clock !== undefined && index.clock !== "pinned") throw new Error(`the record states an unknown clock: ${JSON.stringify(index.clock)}`);
  const at = index?.generated_window?.verified_at;
  return { clock: "pinned", at: Number.isInteger(at) && at > 0 ? at : null };
}

/** Read `<src>/index.json` (a URL or a folder) and return `clockOf` it. Throws when the record cannot be read. */
export async function netClock(src, { timeoutMs = 8000 } = {}) {
  const base = String(src).replace(/\/+$/, "");
  let index;
  if (/^https?:\/\//i.test(base)) {
    const r = await fetch(`${base}/index.json`, { signal: AbortSignal.timeout(timeoutMs), cache: "no-store" });
    if (!r.ok) throw new Error(`${base}/index.json: HTTP ${r.status}`);
    index = await r.json();
  } else {
    index = JSON.parse(readFileSync(`${base}/index.json`, "utf8"));
  }
  if (!index || typeof index !== "object" || Array.isArray(index)) throw new Error("index.json is not a record's index");
  return clockOf(index);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const src = process.argv[2];
  if (!src) { console.error("usage: node tools/net-clock.mjs <record: a URL or a folder holding index.json>"); process.exit(2); }
  try {
    const c = await netClock(src);
    console.log(c.clock === "wall" ? "wall" : `pinned ${c.at ?? ""}`.trim());
  } catch (e) {
    console.error(`net-clock: the record at ${src} could not be read (${e.cause?.code || e.message})`);
    process.exit(2);
  }
}
