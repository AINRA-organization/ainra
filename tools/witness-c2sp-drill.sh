#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# make witness-c2sp-drill — a registrar's log cosigned by a witness this project did not write (D-121).
#
# The witness is litewitness (filippo.io/torchwood), an independent implementation of c2sp.org/tlog-witness that
# public witnesses run. Everything is local and throwaway: a registrar on 127.0.0.1:5932 with its own folder, the
# witness on 127.0.0.1:7391 with its own key in its own ssh-agent and its own database. In order:
#   1. the witness is told the log's origin and its note key, as a witness operator would be
#   2. first submission (old 0): cosigned, and the cosignature verifies under the witness's key
#   3. the log grows: submitted with the consistency proof from the cosigned size, cosigned again
#   4. the submitter forgets what it last sent: the witness answers 409 with its size, and the submitter recovers
#   5. a corrupted consistency proof: refused 422 by the witness
#   6. the witness trusts another key for this origin: refused 403
#   7. the scheduled round (tools/witness-round.sh): cosigns a grown log, skips an unchanged one, idle unconfigured
#
# WITNESS: steps 2 to 4 are the positive controls (an independent witness accepts our notes, proofs and recovery);
# steps 5 and 6 are negative ones (the same witness refuses a bad proof and an untrusted key). If 5 or 6 is accepted,
# or 2 to 4 refused, this drill fails. LITEWITNESS / WITNESSCTL name the binaries (default ~/.cache/ainra-tools/bin).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
BIN="${AINRA_TOOLS_BIN:-$HOME/.cache/ainra-tools/bin}"
LW="${LITEWITNESS:-$BIN/litewitness}"; WC="${WITNESSCTL:-$BIN/witnessctl}"
[ -x "$LW" ] && [ -x "$WC" ] || { echo "witness-c2sp-drill: litewitness and witnessctl are needed:"
  echo "  GOBIN=$BIN go install filippo.io/torchwood/cmd/litewitness@latest filippo.io/torchwood/cmd/witnessctl@latest"; exit 2; }
REG=127.0.0.1:5932; WIT=127.0.0.1:7391; WNAME=example.org/ainra-drill-witness
T="$(mktemp -d -p "${XDG_CACHE_HOME:-$HOME/.cache}" ainra-c2sp-drill-XXXXXX)"
bad=0; ok(){ echo "  ok    $1"; }; fail(){ echo "  ✗     $1"; bad=1; }
rpid=""; wpid=""; apid=""
cleanup(){ for p in $wpid $rpid; do kill "$p" 2>/dev/null; done; [ -n "$apid" ] && kill "$apid" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
for p in 5932 7391; do curl -s -m 1 -o /dev/null "http://127.0.0.1:$p/" && { echo "witness-c2sp-drill: :$p is taken"; exit 2; }; done
TOKEN=drill-token-$$
issue(){ curl -s -m 10 -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" \
  -d "{\"operator\":\"c2sp\",\"lineage\":\"$1\",\"version\":\"1.0.0\",\"tier\":\"L1\",\"auth_class\":\"A2\",\"principal_proof\":\"deadbeefc2sp\",\"capabilities\":[\"read:x\"],\"scope_ceiling\":[\"read:x\"],\"hops\":[]}" \
  "http://$REG/issue" | grep -q '"sub"'; }
submit(){ ./target/release/ainra witness-submit --registrar "http://$REG" --witness "http://$WIT" --state "$T/state.json" \
  --witness-vkey "$WVKEY" --log-vkey "$LVKEY" > "$T/out" 2>&1; }

echo "0 · a registrar, and an independent witness with its own key"
mkdir -p "$T/reg"
AINRA_STAGE=1 AINRA_CLOCK=pinned AINRA_FRESH_KEYS=1 AINRA_STAGE_ISSUE_TOKEN="$TOKEN" \
  ./target/release/registrar-box "$REG" registrar-33 "$T/reg/data" > "$T/reg/log" 2>&1 & rpid=$!
for _ in $(seq 1 40); do curl -s -m 1 -o /dev/null "http://$REG/accreditation" && break; sleep 0.25; done
issue first || { fail "the registrar did not issue"; exit 1; }
LVKEY="$(curl -s -m 5 "http://$REG/note-key")"; LVKEY="${LVKEY%$'\n'}"
ORIGIN="${LVKEY%%+*}"
[ -n "$ORIGIN" ] && ok "the log's note key: ${LVKEY:0:60}…" || { fail "no note key"; exit 1; }
ssh-keygen -q -t ed25519 -N "" -C drill-witness -f "$T/wkey" >/dev/null
eval "$(ssh-agent -s -a "$T/agent.sock")" >/dev/null; apid="$SSH_AGENT_PID"
ssh-add -q "$T/wkey" 2>/dev/null
FPR="$(ssh-keygen -lf "$T/wkey.pub" | awk '{print $2}')"
WVKEY="$(python3 - "$T/wkey.pub" "$WNAME" <<'EOF'
import base64,hashlib,struct,sys
blob=base64.b64decode(open(sys.argv[1]).read().split()[1]); n=struct.unpack(">I",blob[:4])[0]
pk=blob[4+n+4:4+n+4+32]; name=sys.argv[2]
kid=hashlib.sha256(name.encode()+b"\n"+b"\x04"+pk).digest()[:4]
print(f"{name}+{kid.hex()}+{base64.b64encode(b'\x04'+pk).decode()}")
EOF
)"
"$WC" add-log -db "$T/w.db" -origin "$ORIGIN" >/dev/null 2>&1 && "$WC" add-key -db "$T/w.db" -origin "$ORIGIN" -key "$LVKEY" >/dev/null 2>&1 \
  && ok "witnessctl: the witness knows origin $ORIGIN and trusts its note key" || { fail "witnessctl refused the log"; exit 1; }
"$LW" -db "$T/w.db" -key "$FPR" -name "$WNAME" -listen "$WIT" -ssh-agent "$T/agent.sock" > "$T/lw.log" 2>&1 & wpid=$!
for _ in $(seq 1 40); do curl -s -m 1 -o /dev/null "http://$WIT/" && break; sleep 0.25; done
curl -s -m 1 -o /dev/null "http://$WIT/" && ok "litewitness listens as $WNAME" || { fail "litewitness did not start:"; tail -5 "$T/lw.log"; exit 1; }

echo "1 · first submission"
if submit && grep -q "^COSIGNED" "$T/out" && grep -q "verified" "$T/out"; then ok "$(cat "$T/out")"
else fail "not cosigned:"; cat "$T/out"; fi

echo "2 · the log grows; submitted with the consistency proof from the cosigned size"
issue second && issue third
if submit && grep -q "^COSIGNED" "$T/out" && grep -q "verified" "$T/out"; then ok "$(cat "$T/out")"
else fail "not cosigned after growth:"; cat "$T/out"; fi

echo "3 · the submitter forgets what it last sent"
issue fourth; rm -f "$T/state.json"
if submit && grep -q "^COSIGNED" "$T/out" && grep -q "starting again from" "$T/out"; then ok "409 answered with the witness's size, then cosigned: $(grep COSIGNED "$T/out")"
else fail "no recovery from 409:"; cat "$T/out"; fi

echo "4 · a corrupted consistency proof"
issue fifth
old="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["size"])' "$T/state.json")"
note="$(curl -s -m 5 "http://$REG/checkpoint")"
proof="$(curl -s -m 5 "http://$REG/witness-feed?from=$old" | python3 -c '
import json,sys,base64
p=json.load(sys.stdin)["consistency_proof"]
raw=[base64.urlsafe_b64decode(h+"="*(-len(h)%4)) for h in p]
raw[0]=bytes([raw[0][0]^1])+raw[0][1:]
print("\n".join(base64.b64encode(r).decode() for r in raw))')"
code="$(printf 'old %s\n%s\n\n%s\n' "$old" "$proof" "$note" | curl -s -o "$T/resp" -w '%{http_code}' -X POST --data-binary @- "http://$WIT/add-checkpoint")"
[ "$code" = 422 ] && ok "refused 422: $(head -c 80 "$T/resp")" || fail "a corrupted proof was answered $code"

echo "5 · the witness trusts another key for this origin"
"$WC" del-key -db "$T/w.db" -origin "$ORIGIN" -key "$LVKEY" >/dev/null 2>&1
FAKE="$(python3 - "$ORIGIN" <<'EOF'
import base64,hashlib,os,sys
pk=os.urandom(32); name=sys.argv[1]
kid=hashlib.sha256(name.encode()+b"\n\x01"+pk).digest()[:4]
print(f"{name}+{kid.hex()}+{base64.b64encode(b'\x01'+pk).decode()}")
EOF
)"
"$WC" add-key -db "$T/w.db" -origin "$ORIGIN" -key "$FAKE" >/dev/null 2>&1
submit; c=$?
[ $c = 3 ] && grep -q "REFUSED 403" "$T/out" && ok "refused 403: the witness does not trust a note signed by our key for this origin" \
  || { fail "expected 403 (exit 3), got exit $c:"; cat "$T/out"; }

echo "6 · the scheduled round (tools/witness-round.sh): the key trusted again, the log grown, then unchanged"
"$WC" del-key -db "$T/w.db" -origin "$ORIGIN" -key "$FAKE" >/dev/null 2>&1
"$WC" add-key -db "$T/w.db" -origin "$ORIGIN" -key "$LVKEY" >/dev/null 2>&1
issue sixth
export AINRA_HOME_REGISTRARS="http://$REG" AINRA_HOME_STATE="$T/round" AINRA_HOME_WITNESSES="http://$WIT $WVKEY"
if bash tools/witness-round.sh > "$T/round1" 2>&1 && grep -q "^COSIGNED" "$T/round1"; then ok "round 1 cosigned: $(grep COSIGNED "$T/round1")"
else fail "the round did not cosign:"; cat "$T/round1"; fi
if bash tools/witness-round.sh > "$T/round2" 2>&1 && grep -q "skipped" "$T/round2" && ! grep -q "^COSIGNED" "$T/round2"; then
  ok "round 2, nothing new: skipped, no request sent"
else fail "round 2 should have skipped:"; cat "$T/round2"; fi
if AINRA_HOME_WITNESSES="" bash tools/witness-round.sh 2>&1 | grep -q "no witnesses configured"; then ok "no witnesses configured: it does nothing"
else fail "with no witnesses it should do nothing"; fi

[ $bad = 0 ] && echo "WITNESS C2SP DRILL OK: an independent witness cosigned our log twice and through a 409, and refused a bad proof and an untrusted key" \
             || echo "WITNESS C2SP DRILL FAILED"
exit $bad
