#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// tools/registrar-fingerprint.mjs <url-or-file> — the fingerprint of a registrar's accreditation (D-120).
//
// A registrar that the network does not run joins by sending two things through two different channels: the address
// of its registrar, and this fingerprint. The root's holder fetches the accreditation from the address, computes the
// fingerprint again, and signs the registrar into the directory only if the two are equal. Whoever could change what
// the address serves could not also change the fingerprint that arrived by another way.
//
// The fingerprint covers what the directory will vouch for, and nothing that changes in normal operation:
//   registrar, issuer_key, log_root_key, status_key, log_origin, status_uri
// as canonical JSON (sorted member names, no whitespace), SHA-256, written `sha256:<hex>`. A key rotation changes
// it, as it must: the root signs a new directory for new keys only on a new fingerprint.
//
//   node tools/registrar-fingerprint.mjs https://registrar.example.org      (fetches /accreditation)
//   node tools/registrar-fingerprint.mjs accreditation.json
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

export const FIELDS = ["registrar", "issuer_key", "log_root_key", "status_key", "log_origin", "status_uri"];

function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

export function fingerprint(acc) {
  const a = acc && acc.accreditation ? acc.accreditation : acc;
  const picked = {};
  for (const f of FIELDS) {
    if (a[f] === undefined || a[f] === null) throw new Error(`the accreditation has no ${f}`);
    picked[f] = a[f];
  }
  return { id: a.registrar, fingerprint: "sha256:" + createHash("sha256").update(canonical(picked)).digest("hex") };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const src = process.argv[2];
  if (!src) { console.error("usage: registrar-fingerprint.mjs <registrar-url | accreditation.json>"); process.exit(2); }
  let acc;
  try {
    if (/^https?:\/\//.test(src)) {
      const r = await fetch(src.replace(/\/+$/, "") + "/accreditation", { signal: AbortSignal.timeout(10000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      acc = await r.json();
    } else acc = JSON.parse(readFileSync(src, "utf8"));
    const { id, fingerprint: fp } = fingerprint(acc);
    console.log(`${id} ${fp}`);
  } catch (e) {
    console.error(`registrar-fingerprint: ${e.message}`); process.exit(2);
  }
}
