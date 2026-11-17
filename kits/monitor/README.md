<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# Log monitor kit

Anyone may watch a registrar's log; the Standard says so. This is the tool for it. Run it as an operator who wants to
know whether a passport was ever issued in your name without your knowing, or as an independent monitor paid to keep a
registrar honest. Plan: [PLAN-M53 step 11](../../docs/PLAN-M53.md). Decision: D-116.

```
ainra monitor --registrar https://registrar.example --net https://ainra.org/net --roots pinned-roots.json \
              --watch acme --expect acme-passports.txt --state monitor-state.json
```

Each run, offline except for what it downloads:

1. the directory, checked against roots you pinned, gives the registrar's log key (never the registrar's own word);
2. the registrar's current checkpoint must be signed under that key;
3. since the last run, the log may only have grown (a consistency proof), or it raises **FORK** or **ROLLBACK**;
4. the entries are downloaded a page at a time (`GET /log/entries`) and the tree rebuilt: the root must be the signed
   one, so nothing is hidden behind the checkpoint. Between runs the state file keeps the log's compact range (at most
   64 hashes, D-119) instead of the log, so the next run reads only what the log added, in memory that does not grow
   with the log. `--full` reads it all again;
5. every passport under a watched operator's name that is not on that operator's list (`--expect`, one passport
   name per line) is named as **UNEXPECTED ISSUANCE**.

Exit status: 0 nothing found, 3 an alarm, 2 it could not check. It holds no key and changes nothing. The state file
is not advanced past a fork, a rollback, a hidden entry or an unexpected passport, so the alarm repeats until someone
looks (for an unexpected passport: until the operator adds it to its list or has it revoked).

```
make live-up
make monitor-e2e      # an unexpected passport, a hidden entry, a rollback and a fork, each caught; a resumed run
```
