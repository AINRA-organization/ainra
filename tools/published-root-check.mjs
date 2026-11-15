// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// make published-root-check — can the PUBLIC fixed seed still sign for the network this site publishes?  (D-109)
//
// The testbed's root comes from a seed written in the source (crates/ainra-ceremony/src/bin/accredit.rs), so that a
// hermetic drill is reproducible. Until 15 November 2026 the published test network used that same root: anyone
// could run one command and get a directory, naming their own registrar keys, that verified under the roots on
// ainra.org. This is that command, run against ourselves. It signs a directory over the published registrars with
// the public seed and asks the published roots whether they accept it. They must not.
//
//   node tools/published-root-check.mjs           site/net/ must refuse a directory signed with the public seed
//   node tools/published-root-check.mjs --drill   the witness
//
// WITNESS: --drill asks the same question of the committed sample artifacts (kits/verifier/sample-artifacts), which
// ARE under the public seed on purpose: there the forged directory must be ACCEPTED. If this tool ever stops being
// able to forge under the public seed (the seed moved, the tool was changed), the drill goes red, so a green check
// on site/net/ cannot be the tool simply failing to forge.
import { readFileSync, readdirSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Verifier } from "../packages/sdk-ts/dist/index.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const ACCREDIT = ROOT + "target/release/accredit";
const j = (p) => JSON.parse(readFileSync(p, "utf8"));

// A directory over the PUBLISHED registrars' public keys, signed with the public fixed seed: what a stranger can make.
function forge() {
  if (!existsSync(ACCREDIT)) { console.error("published-root-check: target/release/accredit is not built (run it through `make published-root-check`)"); process.exit(2); }
  const regs = ROOT + "site/net/registrars/";
  const accs = readdirSync(regs).map((r) => join(regs, r, "accreditation.json")).filter(existsSync);
  if (!accs.length) { console.error("published-root-check: site/net/ lists no registrar to forge a directory over"); process.exit(2); }
  const out = mkdtempSync(join(tmpdir(), "ainra-forge-"));
  const env = { ...process.env }; delete env.AINRA_ROOT_SEED_FILE; delete env.AINRA_DIRECTORY_EPOCH;
  try { execFileSync(ACCREDIT, [out, ...accs], { env, stdio: "ignore" }); return { directory: j(join(out, "directory.json")), roots: j(join(out, "roots.json")) }; }
  finally { rmSync(out, { recursive: true, force: true }); }
}
const accepts = (roots, forged) => Verifier.fromDirectoryB64(forged.directory, roots.root_ed25519, roots.root_slh) !== null;

const forged = forge();
if (process.argv.includes("--drill")) {
  const sample = j(ROOT + "kits/verifier/sample-artifacts/roots.json");
  if (!accepts(sample, forged)) { console.error("  ✗ the sample roots refused a directory signed with the public seed: this tool can no longer forge, so its green means nothing"); console.error("PUBLISHED-ROOT DRILL FAILED"); process.exit(1); }
  console.log("PUBLISHED-ROOT DRILL OK — the sample roots (under the public seed on purpose) accept the forged directory, so the check can see the fault it looks for");
} else {
  const published = j(ROOT + "site/net/roots.json");
  if (accepts(published, forged)) {
    console.error("  ✗ site/net/roots.json accepts a directory anyone can sign with the public fixed seed");
    console.error("PUBLISHED ROOT IS PUBLIC — the network this site publishes must run under a root from a private seed (D-109)");
    process.exit(1);
  }
  console.log(`published-root-check OK: a directory signed with the public fixed seed over the ${forged.directory.entries.length} published registrars does not verify under site/net/roots.json`);
}
