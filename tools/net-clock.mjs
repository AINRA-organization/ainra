// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// The clock a network states in its published record.
//
// A network's record says which clock it keeps: index.json and registry.json carry `"clock": "wall"` when its
// registrars keep real time (tools/stage.sh publish writes it). No such field, or `"pinned"`, is the pinned clock:
// every signature in the record is made at one fixed instant, and that instant is the record's own
// `generated_window.verified_at`. Everything that reads or drives a network asks here, so nobody has to remember
// which clock a network is on.
//
//   node tools/net-clock.mjs <record>     <record> is a URL or a folder holding the record
//       prints  wall                      read it at the real clock, and name no time in a request
//       prints  pinned <unix seconds>     read it at that instant, and name it in requests
//       exit 2, one line on stderr        the record could not be read: no record, no answer
//
// index.json is read first; a record that ships none (it is optional in a mirror) is read from registry.json, which
// carries the same statement.
//
// The statement is not signed. It chooses how a tool READS a record; it proves nothing about the record. A reader
// that must not be fooled about time (`ainra ctl status`) uses its own clock and takes no word for it.
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** `{ clock: "wall" | "pinned", at: number | null }` from a parsed index.json or registry.json. `at` is the pinned instant. */
export function clockOf(index) {
  if (index?.clock === "wall") return { clock: "wall", at: null };
  if (index?.clock !== undefined && index.clock !== "pinned") throw new Error(`the record states an unknown clock: ${JSON.stringify(index.clock)}`);
  const at = index?.generated_window?.verified_at;
  return { clock: "pinned", at: Number.isInteger(at) && at > 0 ? at : null };
}

/** Read the record at `src` (a URL or a folder) and return `clockOf` it. Throws when the record cannot be read. */
export async function netClock(src, { timeoutMs = 8000 } = {}) {
  const base = String(src).replace(/\/+$/, "");
  const remote = /^https?:\/\//i.test(base);
  // read(file) → the parsed file, or null when the record does not have it; anything else that goes wrong throws.
  const read = async (file) => {
    if (remote) {
      const r = await fetch(`${base}/${file}`, { signal: AbortSignal.timeout(timeoutMs), cache: "no-store" });
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`${base}/${file}: HTTP ${r.status}`);
      return r.json();
    }
    let text;
    try { text = readFileSync(`${base}/${file}`, "utf8"); } catch (e) { if (e.code === "ENOENT") return null; throw e; }
    return JSON.parse(text);
  };
  const stated = (await read("index.json")) ?? (await read("registry.json"));
  if (stated === null) throw new Error("it has neither index.json nor registry.json");
  if (!stated || typeof stated !== "object" || Array.isArray(stated)) throw new Error("its index is not a JSON object");
  return clockOf(stated);
}

// Run as a program (also through a symlinked path: both sides are resolved before they are compared).
const invoked = (() => { try { return realpathSync(process.argv[1] ?? "") === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; } })();
if (invoked) {
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
