# Working handoff — publish & post-publish work

A running document, not project documentation. It exists so the work survives
an interrupted session, and it is current as of the commit that last touched
it — check `git log --oneline -5 -- docs/HANDOFF.md` against `HEAD` if in
doubt.

**Start here every time:**

```powershell
cd D:\code\namespy
git --no-pager log --oneline -8   # what has already landed
git status --short                # must be clean; if not, finish or commit it
gh run list -L 5                  # what CI thinks about it
```

## Status

| | |
|---|---|
| Branch | `master`, pushed, in sync with `origin/master`, **branch-protected** (10 required checks, strict) |
| Suite | 919 passed, 0 failed; clean under `python -O` too (the pytest "assertions stripped" notice there is pytest talking about itself, not this code) |
| Coverage | 89% measured with `pytest -q --cov` (it drifts by a few hundredths between runs, since some transport-retry branches depend on timing); floor 80 lives in `pyproject.toml`, and CI passes `--cov` now — before this round it did not, so the floor was never read there |
| Features | codec, resolver, CLI, truncation/TCP, **EDNS(0) incl. §6.2.2 fallback** (`--no-edns` to disable), **EDNS options** — NSID (`--nsid` / `--advertise-nsid`), COOKIE, Padding, per-server payload sizes (`tests/test_edns.py`) — and **Extended DNS Errors** (RFC 8914) composed by the server and consumed by the resolver and the CLI (`tests/test_edns_error.py`), and **SVCB/HTTPS RDATA** (RFC 9460) decoded into `SvcParams` with `alpn`/`dohpath`, `keyNNNNN` for unregistered keys and §2.4 selection (`namespy/svcb.py`; `tests/test_svcb_rdata.py`, `tests/test_svcb_wire.py`, `tests/test_svcb_presentation.py`), and **MQTYPE** (RFC 10029) in both roles — both options composed and parsed, §3.3's refusals enforced on send and on receive, §3.4's combination merging the extra QTYPEs into one reply and returning the MQTYPE-Response (`namespy/mqtype.py`, `namespy/server.py`; `tests/test_mqtype.py`, `tests/test_server.py`), **and** asked, read and re-asked by the resolver, so one walk answers A + AAAA + HTTPS (`namespy/bundle.py`, `RecursiveResolver.resolve_bundle`, CLI `--mqtype`; `tests/test_bundle.py`, `tests/test_resolver_mqtype.py`), and **the NXDOMAIN cut** (RFC 8020) — `NxdomainPolicy` (`ALWAYS`/`NEVER`/`VALIDATED`) over the QTYPE-free `DnsCache.nxdomain_at()` in both backends, consulted at every hop, with `--no-nxdomain-cut` on the CLI and `NXDOMAIN cut:` in both the trace and the answer (`tests/test_nxdomain_cut.py`, plus the new rows in `tests/test_cache.py`), and the **first leg of DNSSEC** (RFC 4034) — `DNSKEY` and `DS` codecs plus the key tag and DS-digest arithmetic in `namespy/dnssec.py`, with no new dependency: the digests are `hashlib`, and the two published vectors in the RFC are the tests (`tests/test_dnssec_codecs.py`), and **the DNSSEC proof records** (RFC 4034 §3–§4, RFC 5155 §3–§4) — `RRSIG`, `NSEC`, `NSEC3` and `NSEC3PARAM` codecs with type bit maps, the NSEC3 hash and §10.3's iteration ceiling, again with no new dependency (`tests/test_dnssec_proofs.py`) |
| Planning | [`docs/roadmap.md`](roadmap.md) is the completeness matrix and the roadmap — update the row in the same commit as any behaviour change it describes |
| Lint / types | `ruff check` + `ruff format --check` clean; `mypy namespy` exits 0 |
| CI | `ci.yml` (lint, 3.12/3.13 × Ubuntu/Windows, `-O` run, distribution audit), `security.yml` (CodeQL security-extended, dependency-review, pip-audit), `socket.yml` (Socket.dev firewall on installs) — all green on `master` |
| Release | `release.yml` wired end-to-end: tag → build → attest → trusted-publish to PyPI → GitHub Release. **One manual step away — see checklist below.** |
| License | Apache-2.0, `LICENSE` in tree, PEP 639 string metadata |
| PyPI name | `namespy` confirmed unregistered (HTTP 404 on pypi.org and test.pypi.org, 2026-10-28) — register it via Trusted Publisher, not by hand-uploading a wheel |

## The only remaining blocker: first release (manual, ~5 minutes)

GitHub side is done (the `pypi` environment exists, `release.yml` names it).
On python.org — needs a browser session with the PyPI account that will own
the project:

1. PyPI → Account settings → **Publish a project via Trusted Publishing**:
   project name `namespy`, repository `b1tninja/namespy`, workflow name
   `release.yml`, environment `pypi`. Do **not** upload a file first — the
   point is Trusted Publishing; no token exists or is stored anywhere.
2. Then locally: bump `namespy/__init__.py` `__version__` (it is the single
   source — hatchling reads it, and `release.yml` refuses a tag that
   disagrees with it), commit, `git tag v0.1.0`, `git push origin master v0.1.0`.
3. Watch `gh run list`; verify with `pip index versions namespy` and
   `gh attestation verify` against a downloaded artifact.
4. Uncomment the PyPI badges in `README.md`, flip `CHANGELOG.md` Unreleased →
   `## [0.1.0] - YYYY-MM-DD`, update the `SECURITY.md` "never been published"
   wording. Those edits are one commit.

Rehearsal without PyPI: `gh workflow run release.yml -f version=0.1.0` runs
build+attest+audit only (publish will fail on the missing trusted publisher,
which is the correct failure). **Done 2026-10-28, run 40640446010: build job
green (version gate, build, dist audit, SLSA attest, digest, artifact),
publish failed with PyPI's textbook `invalid-publisher: valid token, but no
corresponding publisher` — proof the OIDC half works and only the python.org
form above is missing.** TestPyPI has no trusted publishing; a dry run
there needs an API token in a separate environment — only worth it if step 1
is somehow blocked.

## Commands

```powershell
cd D:\code\namespy
.venv\Scripts\python.exe -m pip install -e ".[dev]"      # venv already exists
.venv\Scripts\python.exe -m pytest -q                    # suite
.venv\Scripts\python.exe -O -m pytest -q                 # see "the -O rule"
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format .
.venv\Scripts\python.exe -m mypy namespy                 # gating in CI
.venv\Scripts\python.exe -m build                        # sdist + wheel
.venv\Scripts\python.exe tools\check_dist.py dist\       # what must be inside them
```

.venv\Scripts\python.exe tools\check_dist.py dist\       # what must be inside them
```

### Environment gotchas (each one cost time already)

- **PowerShell aborts on stderr.** `git push` and `git commit` write progress
  to stderr, which PowerShell surfaces as a NativeCommandError and which
  stops the pipeline *after* the command has actually succeeded. Wrap
  anything that writes stderr: `cmd /c "git push origin master > %TEMP%\o.txt
  2>&1"`, then read the file. Never conclude a git operation failed from
  PowerShell's output alone; verify with `git ls-remote origin refs/heads/master`.
- **Never put a mutating git command and a git read in the same parallel
  tool batch.** Concurrent invocations in one batch race each other: a
  parallel `git status` refreshes the index (that is the phantom
  `index.lock`), and a parallel `git log`/`ls-remote` reads a half-moved
  HEAD and reports commits that just landed as still "modified" or absent.
  The commits are fine — verify sequentially after the chain finishes.
  Run `add && commit && push` as one chained `cmd /c` line and nothing
  else in the same batch.
- **Install with quotes**: `pip install -e ".[dev]"`. Unquoted, PowerShell
  eats the brackets.
- **`Get-Content` misreads UTF-8; it is not corruption.** Windows PowerShell
  5.1 decodes BOM-less UTF-8 as ANSI, so an em-dash renders as mojibake. The
  files are valid UTF-8; editing against the console rendering is how
  mojibake gets *introduced*. **Never use `Set-Content` on source files** —
  it re-encodes and has already produced mojibake here. Use the file editor.

## Rules that must survive further edits

1. **No `assert` on anything that came off the wire.** All validation raises
   `DnsPacketParseError` (defined once in `namespy/wire.py`). `pytest -O`
   must stay green — it is part of the definition of done, not a bonus.
2. **Serialization is canonical and compression-free.** `to_wire()` re-encodes
   full labels, never a pointer, because `cache/sqlite.py` stores
   `bytes(record)` and re-parses it standalone. Received octets stay on
   `.wire` for dumps.
3. **Unknown is not an error.** Unregistered types/classes/RCODEs pass
   through as data (RFC 3597 section 3); never reach for `.value` on the
   result of `parse()`.
4. **RDATA is accounted for inside RDLENGTH in both directions** — overrun
   *and* under-run fail closed (RFC 9267 section 5). The trailing-octet fix
   in `RData_SingleName.parse_from` is the template.
5. **Served TTLs clamp at 2147483647** (RFC 2181 section 8) — `clamp_ttl` is
   called from `DnsRecord.__init__`; do not reintroduce a raw `int(ttl)`.
6. **Attacker-controlled paths log at DEBUG, never louder** (RFC 5358
   section 4.2 rationale). v4, v6 and server now agree; keep them agreed.
7. **Names are octet strings** (RFC 2181 section 11): no LDH screening in the
   parser, comparison is ASCII-folded octets, an interior empty label has no
   wire form and must raise at encode time rather than silently rename.
8. **Protocol behaviour cites its source** — `RFC 9267 section 5` style, in
   code and in `docs/rfc-map.md` (obligation → code → test). Update the row
   in the same commit as the behaviour. Re-check any citation you touch
   **against the body of the document — not a section index, and not your
   memory of the wording.** Pull the text (`get_rfc`, the RFC-Editor mirror
   this machine keeps under `D:\code\rfclibrary\data\mirror\rfc\`, or
   rfc-editor.org) and find the sentence you quote *inside* the section you
   name. A section number can be exactly right while the words inside the
   quotation marks are a paraphrase: that is how RFC 6891's "MUST be ignored"
   shipped here as "MUST be silently ignored", and how RFC 7873 §5.2.2's
   "valid cookie lengths are 8 and 16 to 40 inclusive" circulated in wording
   the RFC does not use. Wrapped lines defeat naive greps — search for a
   fragment that survives the wrap ("valid cookie lengths"), never the whole
   sentence, and confirm the surrounding heading is the one you cited.
9. **Coverage floor is a ratchet**: raise it with tests, never ahead of them — and it
   is only ever *read* when something passes `--cov`, so check the flag is present
   before believing the gate fired.
10. **Transport test fixtures need no backends, and the matrix must see them**: the
    DoT/DoH TLS fixture is the static self-signed pair under `tests/certs`, and the
    CI matrix installs the pure-Python `doh` extra — an optional transport must be
    exercised *and measured* in every matrix job, or the floor goes blind there
    (the DoH commit failed at 78.76% exactly this way: the whole of `doh.py`
    skip-gated on a certificate *generator*). Only the crypto backend stays out
    of the matrix, for the no-backend guarantee; `test_stub_doh.py`'s h2 tests
    keep their own `skipif(not H2_AVAILABLE)` for local runs without the extra.

## Known gaps (deliberate, documented in README/CHANGELOG)

- ~~EDNS(0) on outbound queries~~ — shipped (f15b751), and so are its option
  TLVs, the per-server payload sizes that travel with them, and Extended DNS Errors
  (RFC 8914) in both directions. RFC 9520 shipped too:
  `FailureCache` remembers a failed lookup — including a zone whose servers stopped
  answering — and sends nothing upstream while the entry lives. Dead addresses are
  deliberately not remembered; `--no-failure-cache` turns the whole thing off. See
  [`docs/roadmap.md`](roadmap.md).
- QNAME minimisation: shipped opt-in (`qname_min` / `--qname-min`); the
  default-off is deliberate. serve-stale (RFC 8767), DNSSEC validation
  (RFC 4033/4034/4035), IDN/punycode (RFC 5891), DoT/DoH (RFC 7858/8484)
  remain open.
- ~~Out-of-bailiwick glue filtering~~ — shipped: `classify` takes a referral's
  address records only for a nameserver name inside the zone that answered or
  inside the zone that referral delegates (RFC 5452 section 6 with RFC 1034
  section 4.2.1); anything else is discarded and that server's address comes from
  the `NeedAddress` sub-resolution instead. The lame check for an in-bailiwick NS
  with no glue was already in place.
- `SqliteDnsCache` does synchronous disk I/O on the event loop (latency, not
  correctness); a live-network test tier would lift `resolver.py` coverage.

## Latest round: the NXDOMAIN cut (RFC 8020)

Shipped: §2's SHOULD, as a policy. A NXDOMAIN in the cache now denies the names at and below it,
so the lookup RFC 2308 would send upstream is answered from the denial the zone already made.

**Why the change is in the cache and not the resolver.** §2¶1's claim is about *names* — "all
names and resource record sets (RRsets) at or below that node SHOULD be considered unreachable" —
while a negative entry is
keyed `(name, qtype, class)`. The NXDOMAIN that arrived in answer to an A was therefore invisible
to the AAAA this cut exists to serve, and no amount of resolver-side cleverness fixes a key that
cannot be named. So `DnsCache.nxdomain_at(name, qclass)` is the QTYPE-free lookup `get()` cannot
be: SQLite does it as one read on the primary key's leftmost column, memory keeps an index
maintained on every removal path. The index is not micro-optimisation — the cut is consulted on
every hop of every query, so scanning the cache per hop would cost more than the traffic saved.
The base implementation returns `None` rather than raising: the cut is a SHOULD, so a backend that
cannot answer keeps walking, which *is* the pre-8020 behaviour.

**Two things the tests caught by failing, both mine.** First draft walked only the *ancestors* of
the queried name, which misses the "at" in §2¶1's "at or below that node" — the node is the denied
name, so its other RRsets are covered too — and a AAAA for a name whose A was denied still went
out; the walk now includes the name itself. Second, the alias case (§2¶6: the denied name is the
**last** one in the chain, "and not the QNAME") only
worked once the cut moved inside the per-hop loop rather than being checked once at the origin.

**Policy shape, and where it deliberately differs from `GluePolicy`.** Three stances because RFC
8020 names three: `ALWAYS` (§2¶1's SHOULD, default), `NEVER` (§2 is a SHOULD, and §2¶4 concedes
"The fact that a subtree does not exist is not forever" — this is the watch-a-zone-change switch,
sibling of `--no-failure-cache`), and `VALIDATED` (§2¶3's MAY, cut only on a DNSSEC-validated
denial). `VALIDATED` refuses to construct and says DNSSEC in the message, because it and `NEVER`
emit identical packets while nothing validates; a silent fallback would let an operator believe
proofs were what stopped the cut. `test_validated_policy_is_refused_at_the_door` is the thing that
must change when validation lands. Unlike permissive glue, `NEVER` logs rather than warning on
stderr: it gives up an efficiency, not a defense, and cannot hand a lookup to anyone.

**Visibility, which is the half of the glue precedent worth copying.** A cut's answer is
indistinguishable on the wire from a denial fetched for the name itself — the reply carries the
*ancestor's* SOA beside a question naming the deeper name — so `NxdomainCut` renders as
`NXDOMAIN cut: www.foo.example below foo.example` in the trace and as a `;;` line in the answer.
Both halves are reported in the case the *query* used, not as the cached entry is stored: two names
differing only in case read like two names, and this line exists to be read by whoever just
created the name being denied.

**Overlap with RFC 9520, decided rather than discovered.** The cut is consulted *before* the
failure note, because a cached denial is a proof with an SOA behind it while a failure note is only
a promise not to ask again — and only the first of the two can answer the client.

**Verified**: 870 passed (+37), `ruff check namespy tests` clean, `ruff format --check` clean,
`mypy namespy` exits 0. `docs/roadmap.md` gained its 8020 §2 row; `docs/rfc-map.md` §10 the
code-mapping row.

**Next**: the DNSSEC record codecs (§2¶5's NSEC/NSEC3 echo is one of them), the thing
`VALIDATED` is waiting on. Checking
the RFC while writing this turned up the one obligation here that is *not* shipped: §2¶5 says a
resolver "MUST return these NSEC or NSEC3 records in the response to the triggering query if the
query had the DNSSEC OK (DO) bit set". It is unreachable rather than missing — there are no proof
records to return until the codec exists — but it is the reason the roadmap row is scoped to
§2¶1–¶4 and §2¶6–¶8 rather than to the section. §5¶1 is the known cost of the whole feature, and
the RFC's own answer to it ("This document assumes that such a setup is rare and does not need to
be supported") is why `NEVER` exists rather than a per-zone exception.

### Follow-up: the first DNSSEC leg (RFC 4034 §2, §5, App. B)

`namespy/dnssec.py` (new) plus `RData_DNSKEY` / `RData_DS` in `namespy/rdata.py`, registered on
48 and 43. Chosen because it is the part of DNSSEC with no dependency in it: the public key is
opaque (§2.1.4 defers its format to documents this package does not implement), the key tag is a
16-bit checksum, and the DS digest is `hashlib` over "owner name | DNSKEY RDATA" (§5.1.4). The
dependency decision — RSA/ECDSA/EdDSA for verification — is still ahead of it, untouched.

**The vectors are the RFC's, which is the whole reason to trust the arithmetic.** §5.4 prints a
DNSKEY *and its DS*: key tag **60485**, SHA-1 digest **2BB183AF5F22588179A53B0A98631FAD1A292118**.
Both come out of this code unchanged, in one test, validating the §2.1 layout, §5.1.4's bare
concatenation, and §6.2's downcasing at once. Where no vector exists — the key tag has none for
arbitrary RDATA — the test transcribes Appendix B's C reference a second time and compares.

**Two verified errata change numbers here, and both are pinned.** 4552 rewrites Appendix B's
prose about carries: accumulate at 32-bit precision keeping the carries, fold once, drop only the
carry that the fold itself produces — and the erratum adds that this is "often the same as
reduction modulo 65535, **but not always**", so the shortcut is not used and
`test_key_tag_is_not_reduction_modulo_65535` carries the smallest input where they differ. 193
fixes §B.1's parenthetical for algorithm 1 (RSA/MD5) to "3rd to last and 2nd to last" octets,
which is what its own normative phrase meant; the vector is built so the two readings differ.

**Two things the tests caught before commit, both worth repeating.** The constructors took
`bytes(public_key)` — so the RFC's own Base64 text raised `TypeError: string argument without an
encoding`, and the example that documents the format could not be parsed by the code that
implements it; `key_material()` / `digest_material()` now take octets *or* the master-file text
each field's presentation form specifies (§2.2, §5.3). And `DigestType(15)` raised "not a valid
DigestType", which sends a reader to look for a typo in their zone file when the truth is that
this package has no hasher for 15 — `ds_digest` now refuses by number and names what it does
support. Note the direction the asymmetry runs: **reading is more forgiving than writing**. A DS
with an unknown digest type parses, round-trips and prints; a DNSKEY with Protocol 4 is kept and
reported by `may_verify_rrsets` rather than dropped at parse time, because §2.1.2 puts that
judgement at verification and an operator needs to see which rule the zone broke.

**The repo's own sweep did its job.** `test_rdata_wrapping.py` asserts every registered codec has
a round-trip payload, and it failed the moment the two were added — the new types had to be given
payloads there, which also means they are now covered by the message-level encode/parse/encode
comparison alongside A, SOA and SVCB.

**Next**: RRSIG and NSEC/NSEC3 (4034 §3–§4, 5155), then the canonical-RRset rule of §6.2 — where
erratum 1062 matters, since 4034's list of types whose RDATA names get downcased is incomplete and
RFC 3597 §7 carries the real set — then the wildcard reconstruction from RRSIG's Labels field
(§3.1.3), and only then the verification dependency decision. `NxdomainPolicy.VALIDATED` and
RFC 8020 §2¶5's MUST both clear on the proof-record codecs.

### Follow-up: the DNSSEC proof records (RFC 4034 §3–§4, RFC 5155 §3–§4, §10.3)

`RData_RRSIG` (46), `RData_NSEC` (47), `RData_NSEC3` (50) and `RData_NSEC3PARAM` (51) in
`namespy/rdata.py`, with what they share moved to `namespy/dnssec.py`: the type bit map
encoder/decoder (§4.1.2, reused unchanged by §3.1.8), the NSEC3 hash (§5), base32hex
(§3.3), and §10.3's iteration ceiling as a predicate. Chosen because the codecs are what
everything else in DNSSEC waits on and because, like the first leg, none of it needs a
dependency: SHA-1 is `hashlib`, the bitmap is arithmetic, and a signature is opaque octets.

**Appendix A of RFC 5155 is a test suite the authors wrote on purpose** — "They can also be
used as test vectors for the hash algorithm" — and its twelve hashes are what the new
`test_dnssec_proofs.py` is built on. They cover three traps at once. The alphabet:
**verified erratum 3544** corrects §3.3's "base32" to base32hex, and RFC 4648 §7 warns the two
are not the same encoding; `base64.b32encode` would have produced labels that exist in no
zone. The recursion: §3.1.3's *iterations* is "the number of additional times", so the name is
hashed once regardless and twelve means thirteen invocations — the off-by-one yields a hash
that matches nothing, silently. And the canonical input: §6.2 item 4 keeps the `*` label, which
is why `*.w.example.` has its own hash and why `canonical_owner_octets` is now shared with the
DS digest instead of being named for it.

**`within_validity` is the one rule in `RRSIG` that is not just unpacking.** §3.1.5¶2 allows an
Expiration numerically below its Inception and mandates RFC 1982 arithmetic for these fields, so
the comparison goes through `RData_SOA.serial_ahead` — the same serial arithmetic the repo
already trusted for SOA updates. An integer `inception <= now <= expiration` would have been the
obvious implementation and would have been wrong for signatures that straddle the 2106 wrap.

**The sweep earned its keep again.** Registering four codecs made `test_rdata_wrapping.py`
demand a payload for each, and writing the RRSIG one surfaced a header format of `!HBBIIHI`
where `!HBBIIIH` is correct: the same 18 octets, with the Key Tag read into the Inception Time
and the last field taken from wherever the name started. Nothing else in the suite would have
noticed until a resolver cached a signature that printed a 1970 expiry.

**Not claimed, in order of what now unblocks what.** The §6.2 canonical-RRset rule and the
Labels-field wildcard reconstruction (§3.1.3) are verification-side and were absent at the time of
writing — both have since shipped; see the next section. What the two errata on that rule turned
out to mean is recorded there, because my first account of it ("RFC 3597 §7 carries the real set")
was wrong. Proof *checking* is absent: `NSEC3` exposes
`hash_owner()` for a name, but deciding whether a name falls between this record and
`next_hashed_owner` is §7/§8 work, where **errata 3441 and 4622** both change what a server must
include for empty non-terminals and NSEC3 owner names. RFC 8020 §2¶5's MUST still cannot be
met, and the reason is now specific: the proof records decode, but `DnsCache` stores only the
SOA of a negative answer, so there is nothing to echo when DO is set — storing them is that
row's remaining scope. `NxdomainPolicy.VALIDATED` therefore still refuses to construct, and its
test is still the marker that has to change when validation lands.

**Verified**: 978 passed (+59), `ruff check .` and `ruff format --check .` clean,
`mypy namespy` exits 0, and `python -O -m pytest -q` passes, so none of the new reasoning rests
on an `assert`. Roadmap §6 gained its proof-record row, §10's 8020 row now names the reason
§2¶5 is still open, and `docs/rfc-map.md` §10 maps the new symbols.

**Next**: canonical RRset ordering, then NSEC/NSEC3 proof construction, then the cache change
that lets a denial carry its proofs — and only after those, the dependency decision for
signature verification, which is the one choice here that cannot be undone quietly.

### Follow-up: choosing the cryptographic dependency (and bounding it)

The open decision on the roadmap — "the one choice here that cannot be undone quietly" — is
taken: **`cryptography`, behind a capability-named `crypto` extra**, with `namespy/crypto.py` as
the only module permitted to find it. Verification is still not implemented; what landed is the
boundary and the policy it has to satisfy, so the choice can be reviewed before it is load-bearing.

**Why the extra is called `crypto` and not `dnssec`.** Renaming a published extra breaks every
downstream that installed the old name, and DNSSEC is not the only thing that will ever want
arithmetic here — a TLSA association check (RFC 6698) or any future signature work lands in the
same place. Naming the boundary after its first customer guarantees a breaking change later.

**What the research turned up, so it is not redone.** RFC 9904 Table 2 (Nov 2025) sets "Implement
for DNSSEC Validation" to MUST for 5, 7, 8, 10 and 13 — including the two SHA-1-based RSA numbers
RFC 9905 deprecated *for signing*. A validator still has to verify them, because the zones signed
with them are still out there. That fact alone eliminates every EdDSA-only or modern-only
candidate, and it is why `IMPLEMENT_FOR_VALIDATION` and `SIGNATURE_ALGORITHMS` are two tables with
a test checking they agree: the policy is the RFC's, the capability is the library's, and a gap
between them is something to report to the user rather than a zone to fail on silently.

- **`cryptography` (chosen).** 50.0.2 at this writing; Python Cryptographic Authority under the
  PSF, published security policy with a 48-hour acknowledgement and support for "the main branch
  as well as the most recent release". Covers the whole MUST set plus Ed25519/Ed448. abi3 wheels
  for Windows, macOS, manylinux and musllinux across five architectures, with trusted publishing
  and provenance attestation on every file; Rust (≥1.83) is needed only to compile from source,
  and the floor version installed from a wheel on Windows/3.13 with no toolchain at all.
  Its advisory history is honest reading: of ~19 advisories, three are "Vulnerable OpenSSL
  included in cryptography wheels" — the recurring cost of statically linking OpenSSL, whose fix
  is to upgrade, which is why the floor sits at a current release. One High (Feb 2026) is missing
  subgroup validation for **SECT** curves: unreachable from DNSSEC, since algorithms 13 and 14
  name P-256 and P-384 (prime-order, cofactor 1) — but the reason our layer, not the library,
  decides which curve an algorithm number may mean. None of them touch verification itself.
- **`python-ecdsa` (rejected).** Its own PyPI page says "this library should not be used in
  production settings", it has no RSA — so it cannot do 5, 7, 8 or 10 — and its releases carry no
  provenance. Not close.
- **`pycryptodome` (rejected, with less margin).** Capable and self-contained (own C code, NIST +
  Wycheproof vectors, blinded constant-time paths, Ed448 present), but single-maintainer and
  without the governance or provenance posture above. The fallback if `cryptography` ever stops
  working on a target platform.
- **`PyNaCl` (rejected on scope).** libsodium has no RSA and no NIST P-256, so the MUST set is
  unreachable. Its PyPI page would not load during this pass (bot-blocked), so this rests on
  libsodium's documented feature set rather than a quotation.
- **Pure Python (rejected).** For RSA the exponentiation is the easy part; the hazard is PKCS#1
  v1.5 `DigestInfo` parsing, where the historical forgery bugs live, and RFC 3110 §3¶7 states the
  padding rule in a way that invites a lenient reader ("the FF octet MUST be repeated the maximum
  number of times such that the value being exponentiated is one octet shorter than n"). Writing
  that check by hand is the wrong trade against a promise that was always about *weight*, not about
  never having a dependency.

**The cost, measured here.** A floor constrains other people's environments: this dev box already
had `ubi-reader`, which caps `cryptography<47`, so it and `namespy[crypto]` cannot coexist. That
is the price of demanding a supported line, and still cheaper than no floor — which lets pip
install a release that stopped receiving security fixes. There is no ceiling for the same reason:
a cap in an optional extra of a library protects nobody and guarantees resolver conflicts.

**Homework the verification leg inherits**, all of it encoding rather than arithmetic: RFC 6605 §4
gives ECDSA signatures as fixed-width r‖s, not DER, so `decode_dss_signature` /
`encode_dss_signature` is the bridge (exercised by the new test); a DNSKEY holds an uncompressed
point with the `0x04` tag removed, and `from_encoded_point` is the constructor to use because it
refuses an off-curve point with `ValueError("Invalid EC key")` — asserted, not assumed; RFC 8080 §4
stores EdDSA keys and signatures as raw octets; RFC 3110 §3¶10 permits leading zero bytes in an RSA
signature field, so the codec must not require it to be exactly the key length; and §2's "1 or 3
octets" exponent length plus its prohibition on leading zero octets is still unenforced in
`RData_DNSKEY`, with one verified erratum on RFC 3110 §3 to read first.

**Two bugs the first push found, neither of which this machine could see.** The first was mine in
the test: a plain `from cryptography.exceptions import ...` sat *above* `pytest.importorskip`, so
an install without the extra raised ModuleNotFoundError instead of skipping — all four Test jobs
red while the Crypto job was green. A developer box that has installed the extra cannot
reproduce that, which is the whole argument for the matrix, and the guard is now a call to
`_needs_backend()` that asks the probe rather than an import that duplicates its question.

The second was in the probe, and only surfaced because uninstalling the library left an empty
`cryptography/` directory behind: Python imports that as a **namespace package** — successfully,
with no `__file__` — so `backend()` reported a present backend that had nothing in it. That is the
worst of the two answers, because it sends a caller past the boundary and into an AttributeError
inside verification instead of the `MissingCryptoError` it is built to handle. The probe now
treats a namespace package as absent (`namespy/crypto.py`, with a test that reproduces the
leftover directory). Working out why that test fails when the library *is* installed taught me the
other half of the rule: an empty directory yields only a namespace *portion*, and the finder
prefers a real package from anywhere else on `sys.path`, so the shadow cannot win — the test skips
with that reason stated rather than passing by luck in whichever configuration it landed in.

Both configurations are now exercised on purpose: absent locally and in the four Test jobs (989
passed, 2 skipped), present in the Crypto job (12 passed, 1 skipped).

**Verified**: `ruff check .` and `ruff format --check .` clean, `mypy namespy` exits 0, and the
claim that `import namespy` pulls in no third-party module is now proven in a subprocess — the
only place it can actually be checked.

### Follow-up: the canonical RRset (RFC 4034 §6.2-§6.3, §3.1.3, §3.1.8.1; RFC 3597 §7)

The last DNSSEC work that needs neither a dependency nor a trust anchor: the byte string a
signature is checked against. `canonical_rrset_bytes` / `rrsig_signed_data` and friends in
`namespy/dnssec.py`, `canonical_wire()` on `RData` and each name-bearing codec,
`signed_data_prefix()` on `RData_RRSIG`. `test_dnssec_canonical.py` is 25-odd tests over it.

**I had the downcasing rule wrong last round, and the correction is the interesting part.** I wrote
that RFC 4034 §6.2 item 3's list is incomplete "and RFC 3597 §7 carries the real one". Reading both
sections against their errata says otherwise: **erratum 1062** is raised against 4034 and
**erratum 1063** against 3597, each quoting the other's list, and neither supplies a replacement —
so the two documents disagree in *both* directions and the working answer is the union (3597 §7¶4's
pre-2003 types plus RRSIG and NSEC, which only 4034 names). Two consequences worth knowing before
touching this code: NSEC3 has no embedded domain name to downcase at all (its hashed owner name is
opaque octets, which is what I had imagined wrongly), and RFC 3597 §7¶5 says types defined *after*
it never downcase embedded names — so HTTPS/SVCB keep the case of their target-name, RFC 9460 being
silent on canonical form. A test pins that, because "it has a name in it, downcase it" is the
natural instinct and it is wrong for the newer half of the registry.

**Three traps this section closed.** (1) §3.1.8.1¶5 repeats owner/type/class/TTL/RDLENGTH *inside
every RR* of the signed string; a test measures the ten-octet delta between a one-record and a
two-record set so a future "optimisation" cannot quietly hoist it. (2) §6.3¶2 makes duplicate RDATA
a protocol error an implementation MUST treat as one, allowing leniency only if all but one copy is
dropped — `DuplicateRecordError` by default, `tolerate_duplicates=True` for the other reading.
(3) Canonicalisation is per-codec, not a `lower()` over the RDATA: an MX preference of `0x4142` is
inside the A-Z byte range, so the shortcut corrupts a number while appearing to canonicalise.

**Where a type is listed but we have no codec** (NAPTR, RP, AFSDB, the 1990s remainder),
`canonical_rdata_octets` raises `CanonicalizationError` naming the type instead of hashing raw
octets: guessing where names sit produces a byte string that fails *valid* signatures, and a false
authentication failure is the one outcome a validator must not manufacture.

**Verified**: 1017 passed (+27), `ruff check .` and `ruff format --check .` clean, `mypy namespy`
exits 0, `python -O -m pytest -q` clean. Roadmap §6 gained the canonicalisation row and the
validation row now names precisely what is left.

**Next**, in the order that unblocks the most: RFC 3110 §2's DNSKEY RSA packing (the 1-or-3-octet
exponent length and the leading-zero prohibition) together with **erratum 2811**, which corrects §3
to say RSA signature RDATA **MUST** be zero-padded to the modulus length — the backend will not
infer that padding, so the codec has to; then NSEC/NSEC3 proof checking (§7/§8, errata 3441 and
4622); then the `DnsCache` change that lets a cached denial carry its proofs, which is all that
stands between us and RFC 8020 §2¶5's MUST; then the verification calls through
`namespy[crypto]`, at which point `NxdomainPolicy.VALIDATED` finally has something to mean.

### Follow-up: RSA keys and signature width (RFC 3110 §2-§3, RFC 5702 §2, erratum 2811)

Reading RFC 3110 to write this down removed a stated blocker: §2's DNSKEY public key is integer
packing, not cryptography, so `unpack_rsa_public_key` / `pack_rsa_public_key` in `namespy/dnssec.py`
plus `RData_DNSKEY.rsa_public_key()` and `.require_rsa_key()` give us RSA key material on a default
install. ECDSA and EdDSA key material still waits on `namespy[crypto]`. 16 tests in
`test_dnssec_rsa.py`, none of which need a backend.

**The leading-zero rule is arithmetic, not tidiness.** §2¶3 prohibits leading zero octets in the
exponent and modulus; the reason they must be enforced rather than tolerated is that `key_tag` sums
the RDATA octets, so one extra zero produces a different tag and a DS matching nothing — a correct
key that cannot be used. The same reasoning settled a question the RFC leaves implicit: is the
3-octet length form allowed for a 3-byte exponent? §2¶3's "is represented as one octet if it is in
the range of 1 to 255" reads as prescriptive, and the key-tag consequence confirms it, so
`unpack_rsa_public_key` refuses the long form when the short one was required. I came in intending
to enforce "an empty exponent MUST be an error" from memory; searched the corpus, no such sentence
exists in any RFC, so the code derives that refusal from §2¶2's figure and its docstring says the
rule is read off the layout rather than quoted.

**`MIN_RSA_KEY_BITS` was one constant too few.** RFC 3110 §3¶9 and RFC 5702 §2.1¶2 set the modulus
floor at 512 bits (algorithms 5, 7, 8); **RFC 5702 §2.2¶2 sets 1024 for RSA/SHA-512**. The existing
constant and its test predated that reading, so a validator using it accepted a 512-bit SHA-512 key
RFC 5702 forbids — and because a zone can hold keys of several algorithms, the weakest is what an
attacker forges against. Now `RSA_MIN_KEY_BITS_BY_ALGORITHM` / `minimum_rsa_key_bits()` carry it and
`require_rsa_key()` applies the algorithm's own floor.

**Algorithm 1 is not this format.** RFC 3110 §2's two notes moved RSA/SHA-1 onto number 5 precisely
to separate it from RFC 2537's RSA/MD5, whose RDATA begins with a key-length header; parsing that
with this reader yields a confident wrong key rather than an error. `RSA_ALGORITHMS` is derived from
`SIGNATURE_ALGORITHMS` (`primitive is RSA`) so the two tables cannot drift.

**Erratum 2811 decided a design question that looked arbitrary.** §3¶10 published: "Leading zero
bytes are permitted in the RSA/SHA1 algorithm signature." Verified technical erratum: MUST be added,
so the signature is exactly ⌈bits(n)/8⌉ octets (PKCS #1's `I2OSP(s, k)`). Hence
`rsa_signature_octets` pads short signatures rather than rejecting them — those records exist, and a
backend handed a short one fails in the same shape as a forgery — and refuses a signature wider than
the modulus, since no reduction mod n can produce one.

**Also found for the verification leg: RFC 5702 §8.2's downgrade defence is void** (verified erratum
7090): the claimed protection rests on a signer-side requirement with no validator-side counterpart,
and RFC 6840 §5.11 says explicitly that a validator need not check that every algorithm is present.
So the future "pick an RRSIG from the set" step must choose safely among what arrived instead of
demanding a set shape.

**Verified**: 1033 passed (+16), `ruff check .` / `ruff format --check .` clean, `mypy namespy`
exits 0.

**Next**: NSEC/NSEC3 proof checking (§7/§8, errata 3441 and 4622), then the `DnsCache` change that
lets a cached denial carry its proofs (all that stands between us and RFC 8020 §2¶5's MUST), then
ECDSA/EdDSA key and signature encodings (RFC 6605 §4, RFC 8080 §3 — r‖s, not DER) and the
verification calls through `namespy[crypto]`, at which point `NxdomainPolicy.VALIDATED` acquires
meaning.

### Follow-up: the denial-of-existence proof rules (RFC 4034 §6.1, RFC 4035 §5.4, RFC 4592 §3.3.1, RFC 5155 §6-§9)

New module `namespy/nsec.py`, 26 tests in `test_nsec_proofs.py`. It decides what a set of NSEC or
NSEC3 records *asserts* about a name; it authenticates nothing, exactly as the canonicalisation work
doesn't, so the verification leg still owns the question of whether the records are genuine.

**The most valuable thing here is the error split.** `IncompleteProofError` means the proof records
were not in the response — RFC 4035 §5.4¶6 obliges a resolver to ask again (truncation is why they go
missing, and the third NSEC3 record is the usual casualty), so the caller's move is TCP retry.
`ContradictoryProofError` means the records cannot all be true, where the move is bogus. One error
type for both produces either a retry loop against a correctly-answering server or a forged denial
accepted because retrying eventually looked better.

**Three traps, all now pinned by tests:**

1. *The span wraps.* A zone's last NSEC points at the apex (§4.1.1¶1) and its last NSEC3 at the
   first hash (§7.1¶19), so the second endpoint sorts before the first. The obvious `start < key <
   end` makes that record cover nothing, and every name after the final owner reports unproven —
   i.e. real NXDOMAINs become bogus. Both `name_between` and `hash_between` carry the branch, and
   the one-name zone (equal endpoints) falls out of the same expression.
2. *Some bitmap bits must not be read.* RFC 4035 §5.4¶7 forbids reading the NSEC and RRSIG bits — a
   validated NSEC already proves both exist at its owner, so a signer that omitted them from the
   bitmap must not have it disprove the record carrying it. RFC 5155 §7.1¶5 gives the same reasoning
   for the NSEC3 bit. `test_the_nsec_and_rrsig_bits_are_never_read` and
   `test_nsec3_denies_a_type_at_a_matching_name_only` hold the line; §8.5¶2's empty-bitmap ENT case
   is tested next to them.
3. *§8.3's flag has to survive the step up.* The encloser is found because its child was covered, so
   clearing the flag on a matching parent — the intuitive tidy-up — destroys the proof. Implemented
   literally, in the RFC's own bullet order, and the bogus branch (§8.3¶10: matching while the flag
   is clear means the name exists) is distinguished from incomplete.

Also enforced: §8.3¶12's proper-zone test on the encloser's record (a DNAME, or NS without SOA, means
this server is not authoritative below the name it denies); §8.4's wildcard half, which is what stops
"no such name here" being read as "no answer was due" when `*.example.com.` exists — with RFC 4592
§3.3.1¶4 making that one name to test rather than a wildcard hunt, and §3.3.1¶6-¶7 the reason there
is no fallback to a nearer wildcard; and §8.1/§8.2 filters, including refusing a record set that
mixes algorithm/iterations/salt, since hashes computed under different parameters are incomparable
and a mixed set lets a matching record be paired with an incomparable covering one.

Opt-Out is handled as an assertion problem rather than a flag: `nsec3_proves_nothing` says a covering
Opt-Out record asserts nothing about what it covers (§6¶3 — reading it as a denial is the attack), and
`ClosestEncloserProof.via_opt_out` exists so the resolver can obey RFC 5155 §9.2¶1's AD-bit
prohibition when it gets there.

**My own arithmetic error, caught by the tests:** I asserted `*.example.` sorts between `a.example.`
and `z.example.`. The asterisk is 0x2A, below every letter, so it sorts between the apex and
`a.example.` — the test failed, the span logic was right, and the corrected test now documents where
the label actually falls (the same lesson RFC 4034 §6.1¶4's vector teaches with \001 and \200).

**Not claimed**: §8.5 as amended by **erratum 3441** (No Data for an empty non-terminal under an
Opt-Out span must carry the closest *provable* encloser proof) and §8.6-§8.9 (DS no-data, wildcard
no-data, wildcard answers, referrals to unsigned subzones). Nothing is wired to a `DnsPacket` yet.
Note also **erratum 4622** on the *server* side (§7.2.8): as published its second condition can never
hold, because the NSEC3 type exists at its own owner name — relevant when we have to *accept* such
NXDOMAIN answers.

**Verified**: 1059 passed (+26), `ruff check .` / `ruff format --check .` clean, `mypy namespy`
exits 0, `python -O -m pytest -q` clean.

**Next**, in the order that unblocks most: the `DnsCache` change that lets a cached negative answer
carry its proof records — that is what connects this module to a real response, and it is also all
that stands between us and RFC 8020 §2¶5's MUST; then the response-level validators (§8.5 with
erratum 3441, §8.6-§8.9) and `NxdomainPolicy.VALIDATED`; then ECDSA/EdDSA key and signature
encodings (RFC 6605 §4, RFC 8080 §3) and the verification calls through `namespy[crypto]`.

### Follow-up: cached denials carry their proofs (RFC 8020 §2¶5, RFC 4035 §3.1.1¶3 + §3.2.1)

`NegativeEntry.proofs` — the NSEC/NSEC3 records that denied a name, each followed by its RRSIGs —
now survives both cache backends, including the `nxdomain_at` lookup that answers a name nobody
queried, and `namespy.nsec` gained two adapters: `collect_proof_records()` to pull the bundle out of
a response and `proof_entries()` to feed records into the proof predicates. `test_nsec_cache.py` is
16 tests over the collector, the adapters and both backends.

**The blocker this created, and where it stands: the resolver never set the DO bit, so it was never
sent these records.** RFC 4035 §3.2.1 is not ambiguous — the resolver side of a recursive server MUST
set DO on outbound requests *regardless* of what the client asked, and the name-server side MUST strip
DNSSEC RRs when the client didn't ask but MUST NOT strip types the query explicitly requested. The
first half is done (section below: `dnssec_ok`); the strip half needs the client's DO carried inward
from `namespy/server.py`, and that serving rule is the remaining piece of RFC 8020 §2¶5. I did not
invent an echo to fill the gap: an echo that ignores the strip half of §3.2.1 would hand DNSSEC
records to clients that never asked for any, which is a behaviour change with its own failure modes.

**Two rules that shaped the design:**
* The bundle is whatever §3.1.1¶3 says it is: a proof and its signatures travel together, so an NSEC
  with no covering RRSIG is *dropped* rather than stored bare. A bare proof reaching a client is
  worse than none — it arrives from the one server the client trusts, looking authenticated.
* Pairing is by owner name + Type Covered, not by Signer's Name. The signer is the zone apex; in an
  NSEC3 response the owner is a base32hex hash resembling neither. The natural implementation
  (match on signer) fails exactly where proofs matter, so there is a test named for it.

**Storage notes.** The SQLite column needs a real migration: `CREATE TABLE IF NOT EXISTS` is a no-op
against an existing file, so the schema text alone leaves every on-disk database from an older build
without `proofs` and every read raising `OperationalError`. `_add_proofs_column` checks
`PRAGMA table_info` and ALTERs once; old rows read back with no proofs (the truth about them) and
new writes carry them. An unreadable proofs blob costs the proofs, not the denial — same degradation
`_decode_soa` already applies, and deleting the entry instead would convert a missing signature
bundle into a re-query storm. Positive rows write an empty bundle deliberately: their RRSIGs are
already inside `records`.

**Test failures that were mine, both worth keeping in mind:** `DnsRecord`'s fifth positional argument
is `rdlength`, not `rdata` (pass rdata by keyword); and the SQLite cache key is
`DomainName.canonical_text`, which is uppercased and root-terminated — hand-written SQL in a test
that guessed the spelling silently updated zero rows, which is how a "passing" migration test can
prove nothing. Both tests now use the code's own key function rather than a guess.

**Verified**: 1075 passed (+16), `ruff check .` / `ruff format --check .` clean, `mypy namespy`
exits 0.

**Next, in order**: (1) the DO plumbing — OPT with DO outbound, client DO inward, echo proofs on a
cached denial for DO=1 and strip otherwise (RFC 4035 §3.2.1, RFC 8020 §2¶5); (2) the response-level validators
(§8.5 with erratum 3441, §8.6-§8.9) and then `NxdomainPolicy.VALIDATED`, which can finally mean
something once proofs are both present and checked; (3) ECDSA/EdDSA key and signature encodings
(RFC 6605 §4, RFC 8080 §3) and the verification calls through `namespy[crypto]`.

### Follow-up: the DO bit, and the AD that was pretending to be it (RFC 6891 §6.1.3–§6.1.4, RFC 4035 §3.2.1, RFC 6895)

Storage was finished last increment; this one opens the tap. `RecursiveResolver(dnssec_ok=True)` puts
EDNS(0)'s DO bit on every outbound query, behind new `EDNS_DO_BIT`/`EDNS_CD_BIT` constants in
`namespy/packet.py` that the readers use rather than a bare `0x8000`. The EDNS fallback re-ask drops
DO with the OPT record it removes: a server that just said it cannot do EDNS is not asked for DNSSEC
data a second time (test). Default off, argued in the attribute's own docstring: RFC 4035 §3.2.1's
MUST addresses "the resolver side of a security-aware recursive name server", which is what a caller
becomes when it serves DNSSEC-aware clients; a library that verifies nothing would pay octets per
query and an occasional TCP re-ask for records it cannot use.

**The bug this surfaced, which was shipping**: `DnsMessage.ad` read OPT FLAGS bit 15. Bit 15 is DO —
"please include DNSSEC records". Authentic Data is *header* bit 5 (RFC 6895) and means "I validated
this". Nothing checked the signature, so the CLI's header line printed `ad` for every answer from a
DNSSEC-aware server: a granted request rendered as verified data, in the one place a user looks to
decide whether to trust the answer. The property is `dnssec_ok` now, the CLI reports the bit where it
lives and by its right name (`flags: do` on the EDNS line, as dig prints it), and the header flag
list prints neither `ad` nor `cd`.

**Why the fix removes a flag rather than moving it**: this package's wire format does not model the
header's AD and CD bits at all — the flags field is packed from AA/TC/RD/RA, so bits 5 and 4 neither
parse nor serialise. There was no correct value to print. Restoring `ad` means modelling those two
bits first, which is on the roadmap and is a prerequisite for RFC 5155 §9.2¶1's "MUST NOT set AD when
Opt-Out covers the next closer": a rule about when not to set a bit needs the bit to exist.

**Closed the loop the previous increment left open**: a test drives the resolver's own cache-write
path (`_write_cache`) with a signed NXDOMAIN — SOA, an unrelated MX, NSEC and its RRSIG in one
authority section — and asserts the stored `NegativeEntry` carries exactly the NSEC and its signature
in wire order, MX dropped. That is the only place the three roles separate, so it is where a
regression silently turns an authenticating denial into a bare NXDOMAIN.

**Verified**: 1083 passed (+8 net: 6 DO tests, 2 cache-write tests; 1075 before), `ruff check .` /
`ruff format --check .` clean, `mypy namespy` exits 0.

**Next, in order**: (1) the serving rule — carry the client's DO inward from `namespy/server.py`, echo
proofs on a cached denial to a DO=1 client, strip DNSSEC RRs for DO=0 while never stripping a type the
query asked for explicitly (RFC 4035 §3.2.1¶1-¶2); (2) the response-level validators (§8.5 with
erratum 3441, §8.6–§8.9) wired to `namespy/nsec.py`, then `NxdomainPolicy.VALIDATED`, which can mean
something once proofs are both present and checked; (3) ECDSA/EdDSA encodings (RFC 6605 §4, RFC 8080
§3) and the verification calls through `namespy[crypto]`.

### Follow-up: serving what was asked for — the echo and the strip (RFC 4035 §3.2.1¶1, RFC 8020 §2¶5, RFC 3225 §2)

Asking for DNSSEC data is only half of §3.2.1. The other half is what happens to that data on the way
back to a client, and this closes it: `DNSSEC_SECURITY_TYPES` in `namespy/dnssec.py` (RRSIG, DNSKEY,
NSEC, NSEC3, NSEC3PARAM), `DnsServer._strip_dnssec` withdrawing that set from every section and
recomputing the header counts, and `_synthesize_response` attaching a cached denial's stored proofs to
the answer so RFC 8020 §2¶5's MUST is finally satisfiable end to end. `namespy lookup --dnssec`
reaches all of it from a shell.

**The architectural choice worth keeping**: exactly one line decides whether a client sees these
records — `if not request.dnssec_ok` in `_reply`, immediately before `_apply_edns`. The resolver
always assembles the *complete* answer (its `dnssec_ok` says "I asked the authorities", not "my client
may see this"), and the server narrows it. The tempting alternative — passing the client's DO inward
and having the walk build two kinds of answer — splits one policy across two components and makes the
cache's behaviour depend on who happened to ask, which is how a resolver ends up serving an answer
whose shape depends on cache state from an unrelated client.

**Three judgment calls, all tested, none obvious:**

* *QTYPE=\* is not an explicit request for RRSIG.* §3.2.1's exception is for types the query
  "explicitly requested", and RFC 3225 §2¶5 makes willingness binary: "either the client is willing to
  receive all DNSSEC security RRs or it is not willing to accept any". Letting ANY count would let one
  question type switch the strip off — and the clients §2¶3 reports as *failing* on DNSSEC records are
  exactly the ones that send ANY.
* *A QTx in RFC 10029's bundle list counts as an explicit request.* The QT list is OPT RDATA rather
  than the question section, so reading only `request.questions` would strip the RRSIGs from the answer
  to a client that named RRSIG as a type it wanted. The exception is about what was requested, not
  which field carried the request.
* *DS is not in the set.* §3.1¶1 lists DS among what a signed zone adds for a DO=1 query, so a set
  built from that sentence alone sweeps referrals away — and a DS is a resource record a client can
  name. **The consequence is uncomfortable and is on the roadmap**: a DO=1 walk now carries DS records
  in referrals to DO=0 clients, which §3.1.4 arguably wants and §2¶3 of RFC 3225 argues against. I
  have not measured how many such clients a given deployment would see, so this is recorded as an open
  question rather than resolved by preference.

**Two things this does not do.** The SOA riding along with an echoed denial is unsigned: an RRSIG over
the SOA proves nothing about nonexistence, so it was never stored with the proofs — a gap in what a
client could validate, not a rule broken (§3.1.1¶3 addresses an authoritative server composing from the
zone). And nothing verifies any signature yet: `--dnssec` *shows* records, it does not vouch for them,
which is why the strip is worth having before the validation is.

**Verified**: 1095 passed (+12: 10 serving, 2 CLI), `ruff check .` / `ruff format --check .` clean,
`mypy namespy` exits 0, `-O` run holds, `--dnssec` in `lookup --help`.

**Next, in order**: (1) the response-level validators — §8.5 with erratum 3441, §8.6–§8.9, wired to
`namespy/nsec.py` — then `NxdomainPolicy.VALIDATED`; (2) ECDSA/EdDSA encodings (RFC 6605 §4, RFC 8080
§3) and the verification calls through `namespy[crypto]`; (3) the header AD/CD bits (roadmap), without
which RFC 5155 §9.2's AD rules cannot be honoured. Also worth deciding before a release: the DS strip
question above, and whether `serve --dnssec` should imply DO outbound unconditionally per §3.2.1's
first sentence rather than by flag — currently a server can serve DO=1 clients without ever asking,
which satisfies the strip half and quietly misses the ask half.

### Follow-up: what each response shape owes — the response-level validators (RFC 5155 §8.5-§8.9 with erratum 3441, RFC 4035 §5.4)

The chosen scope for this arc is the full one — validators, ECDSA/EdDSA encodings, and the
verification calls, in staged commits, so that `NxdomainPolicy.VALIDATED` will mean what its
name says; this is the first of those stages, and the door-refusal at `resolver.py` stays
until the chain exists.

**What shipped.** Eight entry points compose the §8.3/§8.4 parts into per-response-shape
validators: `nsec3_proves_no_data` (§8.5 as corrected by verified erratum 3441),
`nsec3_proves_no_ds` (§8.6), `nsec3_proves_wildcard_no_data` (§8.7),
`nsec3_proves_wildcard_answer` (§8.8), `nsec3_proves_unsigned_delegation` (§8.9), and the
NSEC mirrors `nsec_proves_no_data`, `nsec_proves_nxdomain_response`,
`nsec_proves_wildcard_answer` (RFC 4035 §5.4's two bullets, walked with the §8.3 algorithm
and the §8.3¶12 proper-zone test, neither of which needs hashes). Every result names the
records the shape rests on, every failure distinguishes `IncompleteProofError` (§5.4¶6's
ask-again) from `ContradictoryProofError` (§8.3¶10's no-retry-will-help), every NSEC3 entry
point filters through `usable_nsec3` first, and every proof carries `via_opt_out` — §9.2¶1's
AD prohibition, pre-computed for the header bit the roadmap still marks ⬜.

**What the reading taught, three findings.**

1. *Erratum 3441 is a branch, not a footnote.* Published §8.5 demanded a matching NSEC3
   unconditionally; Opt-Out chains hold no record at an insecure delegation (§6¶1), so the
   corrected text lets the closest *provable* encloser proof stand for exactly that case —
   and its first paragraph still reads the bitmap of every matching record. Both paragraphs
   have their own test, and the asserting-cover failure is a contradiction, not a shrug:
   a record that *asserts* QNAME's absence contradicts the No Data response's claim that
   QNAME exists, so retrying changes nothing.
2. *A matching record asserts whatever its span denies* (§6¶4). The matching branches of
   §8.5/§8.6 accept an Opt-Out-flagged record at QNAME — its clear DS bit *is* what
   establishes an insecure delegation — while §8.7 refuses an Opt-Out *encloser proof*: the
   wildcard stands one label above the next closer, synthesis does not cross a zone cut,
   and a signed zone asserts nothing below an insecure delegation.
3. *The asterisk sorts first — a theorem, and two branches fell out of it.* `*.encloser` is
   the first name beneath the encloser, so the encloser's own NSEC span always holds the
   wildcard: as an endpoint (the wildcard exists) or as a cover (it does not). On the NSEC
   side "the wildcard record is missing entirely" is therefore unreachable — the two
   defensive raises carry `# pragma: no cover` with the geometry spelled out, and two tests
   pin the contrapositives: a response whose records *match* the wildcard cannot claim Name
   Error, one whose records *deny* it cannot claim No Data. NSEC3 has no such theorem —
   hashes reorder the zone — which is why §8.7's missing-wildcard case has a test at all.

**My own arithmetic error, caught by the tests again**: I derived §8.8's next closer from
QNAME's leftmost label, which for `x.y.example.com.` under `example.com.` produced
`x.example.com.`. The next closer is the encloser with *one* label added — `y.example.com.`,
per §5's definition and the tested §8.3 walk. The implementation had the wrong index; the
test's assertion was right. Same lesson as the asterisk-sorting one above it: derive from
the definition, not from the shape of the name string.

**A pre-existing flake, fixed in its own commit**: the name round-trip fuzzer placed
`assume(len(bytes(name)) <= MAX_NAME_OCTETS)` *after* the encoding that raises when the
budget is blown — a stored six-label counterexample (39-to-40 octet labels) made every
local run red where CI's fresh `.hypothesis/` database stayed green. The bound is now
arithmetic over the labels before `from_labels`, in both properties that had it inverted.

**Not claimed**: nothing consumes the validators yet — same position §8.3/§8.4 shipped in,
the consumer is the validation pipeline — and nothing verifies a signature;
`NxdomainPolicy.VALIDATED` stays refused at the door until the chain exists, its message
still honest. Erratum 4622 on the *server* side (§7.2.8) still waits for the day this
server has to *accept* such NXDOMAIN answers rather than compose them.

**Verified**: 1138 passed (+44 in `tests/test_nsec_responses.py`; the fuzz fix changes no
counts), `ruff check .` / `ruff format --check .` clean, `mypy namespy` exits 0, `-O` run
holds, coverage 91% total with `namespy/nsec.py` at 98%.

**Next, in order**: (1) ECDSA/EdDSA key and signature encodings (RFC 6605 §4, RFC 8080 §3) —
fixed-width r‖s rather than DER, which is exactly the trap that section exists to warn
about — then the verification calls through `namespy[crypto]`, RFC 4035 §5.3.1's procedure
with RFC 9904's policy table; (2) trust anchors and the DS→DNSKEY chain (root KSK fetched
from IANA at implementation time, not from memory — rolling it is roadmap ⬜ and an embedded
stale anchor would fail every query); (3) `NxdomainPolicy.VALIDATED` wired where
`_nxdomain_cut` reads `NegativeEntry`, which is finally what makes its door-refusal
liftable; (4) the header AD/CD bits, without which §9.2's rules and this round's
`via_opt_out` flags honour nothing. The DS-strip question and the `serve --dnssec` DO
question above remain open.

### Follow-up: the ECC encodings — fixed-width field elements, bare bit strings, and a DER parser that reads each blob once (RFC 6605 §4, RFC 8080 §3–§4, erratum 4935)

The second stage of the staged arc: the key and signature *encodings* for ECDSA and EdDSA,
with the verification calls still ahead of them. The promise this section keeps is that all
of it needed no dependency — the last round's note in `namespy/crypto.py` said the ECDSA and
EdDSA halves "turned out to be layout rather than arithmetic", and they did.

**What shipped.** `namespy/dnssec.py` gained the layout: `pack_ec_public_key` /
`unpack_ec_public_key` (x‖y at two padded field elements, §4¶1), `ecdsa_signature_from_rs` /
`ecdsa_signature_from_der` / `ecdsa_signature_to_der` / `ecdsa_signature_octets` (the wire is
fixed-width r‖s, §4¶2; DER exists only at the backend boundary), and
`eddsa_public_key_octets` / `eddsa_signature_octets` (bare bit strings at 32/57 and 64/114,
RFC 8080 §3–§4). `namespy/crypto.py` gained the policy tables beside the algorithm registry:
`ECDSA_FIELD_OCTETS`, `EC_KEY_OCTETS`, `EC_SIGNATURE_OCTETS`, `EDDSA_KEY_OCTETS`,
`EDDSA_SIGNATURE_OCTETS`, and the derived `ECDSA_ALGORITHMS` / `EDDSA_ALGORITHMS` sets.
`RData_DNSKEY` gained `ec_public_key()` / `require_ec_key()` / `eddsa_public_key()` /
`require_eddsa_key()` next to the RSA pair; parse still never interprets. The DER parser is
strict where the grammar is permissive to lookalikes — short-form lengths only (two field
elements plus sign pads cannot reach 128 content octets, so the long form encodes nothing
these curves sign), minimal INTEGERs, one reading per blob.

**Findings.** (1) *The published examples disagree with copy-paste, in both directions.* The
RFC 6605 §6.1 key wraps mid-character-group in the .txt and a hand transcription drops the
`b` at the wrap — caught only because the key-tag and DS-digest tests refuse a key whose
octets are off by one, which is exactly what those pins exist for; the vectors in
`test_dnssec_ecc.py` were extracted programmatically and accepted only after §6's own printed
tags (55648, 10771) and digests matched. (2) *RFC 8080 §6 as printed is wrong*: verified
erratum 4935 replaced every RRSIG example after the generator script dropped the algorithm
identifier and counted the root label, and the corrected values are on the erratum page, not
in the RFC body. The tests pin the corrected Ed25519 and Ed448 signatures **verifying**
through the backend and the superseded original **failing** — a copy-paste of the document
alone would have pinned broken values and called them vectors. (3) The coordinate rule is
RSA's rule inverted: pack pads to field width (FIPS 186-3's fixed-width bit strings) where
RFC 3110 §2¶3 prohibits leading zeros, because a coordinate's width is the curve's, not the
value's — and uniqueness matters either way, because the key tag sums the octets a DS
commits to. (4) DER's zero INTEGER is the single octet `0x00` — a minimality check written as
"no leading zeros" rejects the canonical encoding of zero; the check now distinguishes the
sign pad (`0x00` before a high-bit octet, required) from surplus padding (refused) from the
zero itself (parsed, then refused as not-a-signature, which is where it belongs). (5) Ed448's
widths are 57 and 114 — not multiples of eight — which the tests name explicitly because the
natural heuristic fails every Ed448 record on the wire. (6) `cryptography` 50 removed
`Encoding.Uncompressed` in favour of `Encoding.X962`; the crypto extra's floor (50.0.2) is
already at that API, and the local venv now installs `namespy[crypto]`, so the backend-gated
tests run here rather than only in the CI crypto job.

**Not claimed.** Nothing verifies a network response yet: the RFC 4035 §5.3.1 procedure
(signtime window, protocol 3, key-tag match, algorithm policy per RFC 9904) is the next
commit, and until it lands `NxdomainPolicy.VALIDATED` stays refused at the door with its
honest message. The backend signatures verified here are the RFCs' own examples, which pins
the encodings, not a validator.

**Verified**: 1180 passed (+42: 41 new in `tests/test_dnssec_ecc.py`, plus 1 previously
backend-skipped test that the now-installed extra enables; 1 skipped is the namespace-shadow
case that needs the distribution absent), `ruff check .` / `ruff format --check .` clean,
`mypy namespy` exits 0, `-O` run holds, coverage 91% total with `namespy/dnssec.py` at 99%.

**Next, in order**: (1) the verification calls — RFC 4035 §5.3.1's procedure over
`namespy[crypto]`: canonical RRset reconstruction (already shipped), RRSIG signtime/protocol/
key-tag checks, RFC 9904's algorithm policy at the point of use, and the per-primitive
backend dispatch this encoding work now feeds; (2) trust anchors — the root KSK fetched from
IANA at implementation time rather than from memory, and the DS→DNSKEY chain; (3)
`NxdomainPolicy.VALIDATED` wired where `_nxdomain_cut` reads `NegativeEntry`; (4) the header
AD/CD bits. The DS-strip question and the `serve --dnssec` DO question remain open.

### Follow-up: the verification procedure — §5.3.1 with three outcomes, not two (RFC 4035 §5.3.1, RFC 9904 at point of use)

The third stage of the staged arc: the RFC 4035 §5.3.1 procedure, its dispatch through
`namespy[crypto]`, and the first signatures verified end to end by this package rather
than by its encodings alone.

**What shipped.** `namespy/verify.py` — one function, `verify_rrsig(rrsig, owner, rdatas,
dnskeys, *, now, rclass)`, returning a `SignatureVerdict` over three outcomes; and
`crypto.verify_dnskey_signature(algorithm, key_material, signature, message)`, the single
primitive dispatch that owns layout (via `namespy.dnssec`), the DER boundary, erratum
2811's RSA padding, and the RFC 5702/3110 size window — a key outside its window cannot
reach arithmetic at all, which is where the downgrade surface actually closes: the zone
chooses which of its keys the RRSIGs can be checked against, and the weakest one must not
get a turn. The checks run cheapest-first so the *reason* a validator stopped is the
first true one: RFC 9904 policy, window, reconstruction, key matching, arithmetic.

**Findings.** (1) *Three outcomes are the deliverable, not garnish.* RFC 9904 §1.2¶3
marks RSAMD5/DSA MUST NOT "so that recursive resolvers can remove support for validating
it" — which maps to INVALID, and deliberately *ahead of the backend probe*, so the answer
cannot vary by install (a test drives it with the backend monkeypatched away). Unreadable
material, an absent extra, an unregistered algorithm map to UNSUPPORTED instead: RFC
4035 §4.3¶5's Indeterminate exists because "we could not check" reported as "it is forged"
is the failure mode that turns a broken path into a denial. (2) *The key tag is a
weighted checksum, and my own test tripped on it*: constructing a tag-preserving twin by
trading +1/-1 across *adjacent* key bytes moves the tag by exactly 255 — Appendix B
shifts alternating octets by eight, the very weighting erratum 4552 is about. Same-parity
trades preserve it. (3) *No RFC anywhere publishes an RSA RRSIG* — RFC 3110 and RFC 5702
print keys but no signed example — so the RSA leg is pinned by deterministic PKCS#1 v1.5
round-trips and the absence is stated in the test docstring rather than papered over; one
round-trip is RSASHA1, pinning that RFC 9904's MUST for validation survives RFC 9905's
signing deprecation, because a validator that refused would report live zones bogus.
(4) *Disqualified candidates must be built tag-recomputed*: flags and protocol are part
of the RDATA the tag sums, so a protocol-2 DNSKEY no longer matches the published tag —
the test's first draft landed in the ¶8 "no matching DNSKEY" branch instead of the
protocol branch it meant to reach. (5) *The backend's Ed25519 loader does not validate
points* — only length — so a tampered EdDSA key verifies-and-refuses (INVALID, an attempt
that ran) where a tampered ECDSA key is refused at key-build (UNSUPPORTED, no attempt);
`attempts` counts only arithmetic that ran, and the two paths document themselves by
disagreeing. (6) §5.3.1's ¶2/¶3 owner/class/zone equalities are RR-header facts an RDATA
cannot see, and ¶11-¶13 key authenticity is the trust-anchor stage: the docstring says a
VALID verdict means "a key in the set you handed me signed these bytes" and nothing more.

**Not claimed.** Nothing consumes `verify_rrsig` yet: the resolver still refuses
`NxdomainPolicy.VALIDATED` at the door, because without a trust anchor the keys the
procedure checks are unauthenticated by ¶11-¶13 — honest about what it says, not what it
proves. The DS→DNSKEY chain and the root anchor (fetched, not embedded from memory) are
the next commit; AD/CD header bits still outstanding for §9.2.

**Verified**: 1206 passed (+26 in `tests/test_dnssec_verify.py`), `ruff check .` /
`ruff format --check .` clean, `mypy namespy` exits 0 (21 modules), `-O` run holds,
coverage 91% total with `namespy/verify.py` at 100% and `namespy/crypto.py` at 94% (the
rest is the probe's namespace-shadow path and defensive refusals).

**Next, in order**: (1) trust anchors — the root KSK fetched from IANA at implementation
time rather than from memory, the DS→DNSKEY chain, and the self-signature path §5.3.1
already handles; (2) `NxdomainPolicy.VALIDATED` wired where `_nxdomain_cut` reads
`NegativeEntry`, consuming proofs whose records verify through `verify_rrsig` — which is
finally what makes its door-refusal liftable; (3) the header AD/CD bits. The DS-strip
question and the `serve --dnssec` DO question remain open.

### Follow-up: trust anchors and the first live chain (RFC 9718 §2-§3, RFC 4035 §5.2, RFC 4034 §5)

The fourth stage: a trust point that arrives from its live publication rather than a
constant, and the DS→DNSKEY link that lets `verify_rrsig`'s answer mean something. For the
first time this package authenticated a response from the running Internet — the root
itself — and says so in a test.

**What shipped.** `namespy/anchors.py` — `TrustAnchor` (RFC 9718 §2.2's KeyDigest in
object form, including the optional PublicKey/Flags pair §2.2¶12 added), `parse_root_anchors`
(the §2.1 RELAX-NG schema enforced line by line), `fetch_root_anchors` (§3.1¶3's URL over
HTTPS, transport injectable), `active_anchors` and the §2.2¶7 windows, and
`matches_dnskey` (RFC 4035 §5.2¶4's tag+algorithm+digest, RFC 4034 §5.2¶1's bit-7 proviso).
`namespy/verify.py` gained `authenticate_dnskey_rrset` — §5.2¶2-¶5 for one zone, returning
SECURE/BOGUS/INDETERMINATE with the matched key tag — composing `verify_rrsig` for the
apex self-signature rather than re-doing any of it.

**Findings.** (1) *RFC 7958 is obsolete, superseded by RFC 9718 (2025-01)* — every handle
on "the root anchor file" from memory points at the wrong document. 9718 removed the
self-signed PGP message and the CSR (§3.3: they mixed out-of-band trust of authentication
keys with out-of-band trust of the DNSSEC keys) and left TLS as the content-and-origin
assurance (§3.2¶4), with the detached CMS signature optional. The module therefore does
not pretend to authenticate the file: schema plus transport, and says so. (2) *The live
file already carries three keys* — the withdrawn 19036 (validUntil 2019-01-11), 20326,
and the 2024 KSK 38696 — and the two current ones now ship their public keys inside the
XML, so the §2.2¶7 window logic is load-bearing on day one, not at some hypothetical future
rollover. (3) *The fixtures cross-check each other*: the DS digests computed from the DNSKEY
RRset fetched from DNS equal the Digest elements from the independently-fetched IANA file,
for both live KSKs — the pin that makes an embedded fixture trustworthy without asking anyone
to trust the session that captured it. (4) *Getting signed data out of this network was its
own investigation*: UDP/53 is intercepted (forged 12–17-byte answers to the root servers'
anycast addresses) and the first DoH answers came back identical-but-unsigned from two
providers — which was my own one-octet-short OPT record killing the DO bit silently. Two
independent providers agreeing on an unsigned 842-byte answer is exactly what a stripping
middlebox looks like, and the fix was to check the query bytes, not the network story; the
corrected query returned the signed set (1139 octets, RRSIG included). (5) *The ZSK trap*:
flags 256 IS the zone-key bit (0x0100) — a DS may legitimately point at a ZSK — and the
first draft of the §5.2¶1 test asserted the opposite with a 256-flags record and passed
nothing; the real non-zone-key case is flags 1. (6) *¶5 means the matched key's own
signature*: 20326 matches an active anchor and sits in the RRset, but only 38696 signed
it, so trusting 20326 alone is BOGUS — the KSK-ceremony moment that a
"any-verified-key-will-do" shortcut would silently wave through. (7) *Tag collisions are
refused before arithmetic*: a signature bearing the matched key's tag but signed by another
zone (signer "com.") is not evidence about the root; the signer comparison is §5.2¶5's, and
16 bits cannot carry it.

**Not claimed.** The resolver still consumes none of this: `NxdomainPolicy.VALIDATED`
refuses at the door until the walk fetches DS RRsets across zone cuts and feeds them here.
One link is verified, not the chain end-to-end below the root — a child zone's DS fetch,
insecure-delegation handling via proved-nonexistence of DS (§5.2¶7), and RFC 8509-style
anchor maintenance remain open; nothing refreshes the anchor document on its own schedule,
and the detached CMS signature (§3.2¶3) is deliberately unimplemented, matching the
document's own trust model.

**Verified**: 1249 passed (+43 in `tests/test_dnssec_anchors.py`), `ruff check .` /
`ruff format --check .` clean, `mypy namespy` exits 0 (22 modules), `-O` run holds,
coverage 91% total with `namespy/anchors.py` at 94% (the rest is the urllib transport
body, which tests inject past) and `namespy/verify.py` at 98%.

**Next, in order**: (1) `NxdomainPolicy.VALIDATED` — the resolver walk fetching DS RRsets
at each cut, `authenticate_dnskey_rrset` composing them root-down, §5.2¶7/¶10 routing
insecure and unsupported children, and `NegativeEntry` proofs whose records verify through
`verify_rrsig`; (2) the header AD/CD bits (§9.2, 6895, 8145). The DS-strip question and the
`serve --dnssec` DO question remain open.

### Follow-up: the four-state layer — `namespy/validate.py` (RFC 4035 §4.3, §5.1, §5.2¶6-¶7, §5.3.4; RFC 4033 §5)

The fifth stage: the layer that answers the question the previous four stages were all
local about. Not "does this signature hold" but "may this answer be believed" — the
four states RFC 4035 §4.3 requires a security-aware resolver to name, now decided from
whatever records a walk has accumulated, across as many responses as the chain needs.

**What shipped.** `namespy/validate.py` — `DnssecStore` buckets records into RRsets that
remember which zone's data they arrived in (RFC 4035 §5.3.2¶18: at a delegation the parent
and the child each hold an NSEC at the same name, and the two "MUST NOT be combined");
`Validator.authenticate_zone` climbs from any zone to a trust point — a DS- or
DNSKEY-shaped anchor (RFC 4033 §2 allows either; `authenticate_dnskey_rrset` gained the
`trusted_dnskeys` parameter that consumes RFC 9718 §2.2¶12's optional PublicKey element),
an authenticated parent's DS, or the parent's signed proof that no DS exists; and
`validate_rrset` / `validate_denial` decide answers, wildcard-expanded answers (§5.3.4¶1's
closer-match proof, required and verified), and denials — geometry through the nsec.py
predicates, then signatures over every record in the proof bundle. `verify.py`'s
three-way outcome propagates upward unchanged: missing data says Indeterminate,
contradicted data says Bogus, and the two never trade places. `namespy/validate.py` is
not re-exported from the package root, same as its predecessors.

**Findings.** (1) *A wrong citation was living in six files*: the last two rounds credited
the Indeterminate state to "RFC 9080 §3.1" — RFC 9080 is the Homenet profile of Babel
(author Chroboczek; nothing to do with DNSSEC). The states' actual home, checked against
the document itself per rule 8, is RFC 4035 §4.3, with RFC 4033 §5 as the variant and RFC
9499 §11 reprinting both verbatim while declining to reconcile them. All eight occurrences
are corrected, and the correction is recorded in the roadmap row it touches. (2) *Origin
bucketing is not tidiness*: a (name, type)-keyed store merges the parent's NSEC for a
delegated name with the child's NSEC for its own apex — one RRset matching neither
signature, every signed delegation a self-inflicted bogus; the RRSIG's Signer's Name is
its own origin for free, and a test pins the split. (3) *A missing signature is Bogus, not
Indeterminate* — RFC 4033 §5 lists "missing signatures" under Bogus literally, and §4.3¶5's
"not able to obtain" is about absent records, not un-signed present ones; the two refusals
read alike until you notice one is evidence of tampering. (4) *INSECURE must be earned by a
verifying proof*: with the no-DS NSEC's signature octet flipped, the unsigned child is
BOGUS, not downgraded — strip-a-DS-sign-the-lie turns every name below a subtree over to
whatever the path answers, which is the attack RFC 4033 §5's phrase "signed proof" exists to
close. In the combination order, BOGUS outranks INSECURE outright. (5) *The parent's
verdict is a result, never a veto* — §5.1's islands and §5.2¶7's "MAY re-establish an
authentication path": the directly-anchored zone stays SECURE below a parent whose DS was
tampered with, and the walk's memo makes that one climb per zone per lookup. (6) *Expired
is Bogus too*: the window is a check that ran and refused; "could not tell" would invite
retrying stale data into permanence instead of the re-sign that fixes it. (7) The
wildcard's synthesising name is reconstructed from the one octet that remembers it — the
RRSIG's Labels — and the closer-match proof is then verified like the rest of the bundle,
because a wildcard is only as strong as the denial that nothing closer exists. (8) *CI
caught what the green local run could not*: the fixture generated its three RSA keys at
import, and CI's matrix runs pytest without `namespy[crypto]` — collection died on
`ModuleNotFoundError` before any skip guard could say its piece, the exact failure the
guard pattern exists for. Keys now come from cached accessors on first use, and the one
test that monkeypatches the backend *after* building the tree needed its own gate; the
lesson generalises to any test whose fixture touches the optional extra at module level,
and the local suite cannot surface it on a machine that always has the backend installed.

**Not claimed.** The resolver still consumes none of it: `NxdomainPolicy.VALIDATED`
refuses at the door, its message now naming the true gap — the walk must *fetch* DS and
DNSKEY RRsets at cut time and keep them available to a `Validator`, which is wiring plus
a caching question (DNSKEY/DS have no place in the current entry model yet), not more
verification logic. Nothing here touches the wire, the caches, or the AD/CD bits; the
`now` a resolver would pin per lookup is threaded but nothing live calls it.

**Verified**: 1294 passed (+45 in `tests/test_dnssec_validate.py`), `ruff check .` /
`ruff format --check .` clean, `mypy namespy` exits 0 (23 modules), `-O` run holds,
coverage 92% total with `namespy/validate.py` at 97% (the remainder: defensive arms —
unsigned-proof propagation and the unreachable wildcard contradictions) and the whole
45-test file passing without network: a three-level RSA-signed tree, both NSEC and NSEC3
legs, broken one octet at a time, plus the captured live root validated end to end as an
answer through the new layer. The crypto-free parity run (cryptography import blocked by
a PYTHONPATH shim — how CI's matrix legs see it) lands at 1229 passed / 66 skipped / 0
errors after the lazy-key fix; CI on the first commit proved this check worth scripting.

**Next, in order**: (1) the header AD/CD bits (§9.2, 6895, 8145) — the verdict now
exists at the moment an answer leaves the resolver, and asserting it honestly is the
next consumer; (2) the DS-strip question and the `serve --dnssec` DO question remain
open. The wiring itself landed the round after this one — see the section below.

### Follow-up: the wiring — `NxdomainPolicy.VALIDATED` honoured (RFC 4035 §5.2¶6, §4.1¶1, §4.5; RFC 8020 §2¶3)

The door that had stood since the RFC 8020 round — "the walk cannot yet produce a
verdict at cut time" — is gone, and the gap it described is what this round built:
`resolve_steps(..., anchors=...)` validates the negatives it receives.

**What shipped.** Every response of the walk — referrals included — is filed into one
`DnssecStore` per lookup with the responding zone as origin, which is how §3.1.4's
piggybacked DS arrives for free (two of the chain's three links cost no query at all).
A terminal NXDOMAIN/NODATA is judged under the anchors before its cache write; whatever
the chain lacks comes back as a `ValidationVerdict.fetch_hint` — `(name, rtype,
from_zone)` — and the walk spends its own `SendQuery` effect on it, mid-lookup, asked of
the zone that holds it (§5.2¶6's MUST-query is the named case; the loop is capped by
both the Validator's once-per-triple ledger and `_MAX_SEC_FETCHES`). The verdict yields
a `DnssecVerdict` event — rendered by `--trace` beside its zone, chain queries marked
`(dnssec)` — and a SECURE one is stamped into the cached `NegativeEntry.validated`,
persisted through SQLite by a column migration that reads old rows, honestly, as
unvalidated. `NxdomainPolicy.VALIDATED` reads that stamp at the cut; the door now
refuses only the configuration error it always should have — VALIDATED without anchors.
`RecursiveResolver(trust_anchors=...)` forces DO (RFC 4035 §4.1¶1: records never asked
for are records never checked), and the CLI gets `--validate`, `--trust-anchor FILE`
(RFC 9718 XML; an all-expired file is a refusal, not a fallback) and `--validated-cuts`.

**The decision worth keeping**: stamp at write, filter at cut, never re-verify at cut.
A remembered verdict matches RFC 4035 §4.5's atomic-entry model — the denial and its
proof live and die on one TTL — while re-checking at cut time would let a DNSKEY's
expiry accident decide a policy question, and would need the chain re-fetched by a walk
whose whole point is not to query. The `validated` flag is a record of a check this
resolver performed, which is also exactly what it means across a restart or an old
database: nobody checked, so no cut.

**Verified**: 1325 passed (+31: 12 `tests/test_dnssec_wiring.py` — the scripted
three-zone descent pins secure/stamp/zero-network-cut, forged-proof bogus that re-walks
instead of cutting, both insecure-delegation shapes including the live §5.2¶6 DS query,
indeterminate-on-deaf-servers, the unvisited-zone hint that must not query the wrong
server, and NODATA stamping; 7 validator fetch-hint tests; 5 cache-flag tests; 7 CLI
flag tests; the door test rewritten), `ruff check`/`format` clean, `mypy namespy` exits
0, coverage 92% total.

**Next, in order**: (1) the header AD/CD bits (§9.2, 6895, 8145) — with them, positive
answers get judged for the answer's own `AD`, and the serve path can assert or strip
honestly; (2) the DS-strip question and the `serve --dnssec` DO question remain open.

### Follow-up: the AD/CD bits — a verdict the wire can read (RFC 4035 §2, §3.2.2–§3.2.3, §4.6–§4.7; RFC 6895 §2; RFC 6840 §5.7–§5.8; RFC 5155 §9.2; RFC 9520 §3.4; RFC 8914 §4.7)

**Requested**: the last item the DO-round left standing — the header pair
did not exist, so nothing could assert, honour, or even read validation
without lying.

**Delivered**: `DnsPacket` models AD (bit 5) and CD (bit 4) per RFC 6895 §2's
reallocation (Z shrinks to the one bit still its own — pack, parse, and the CLI's
re-printed `ad`/`cd` all moved to the registry's layout), and every rule about
the pair landed beside the verdict it rests on. AD is asserted only where this
resolver judged: on a SECURE denial's response, on cache answers read from a
SECURE stamp — never by an anchorless reader (§3.1.6¶3: no trust point, no
claim), never across an Opt-Out proof (`ValidationVerdict.via_opt_out` surfaces
RFC 5155 §9.2¶1's MUST NOT; `ad_worthy` = secure ∧ ¬opt-out, one property so no
caller can honour the rule halfway), gated at the server on the client having
signalled DO-or-AD (RFC 6840 §5.8), and upstream copies are cleared on arrival
because §4.6¶3 says bits over unauthenticated UDP mean nothing. CD rewrites what
failure means: `resolve_steps(..., client_cd=...)` stops interfering — the Bogus
denial is delivered with AD down, un-noted (§4.2¶2 waived the check), and uncached
(the poisoning door a CD-fetched unvalidated entry would open for the next non-CD
client — with no chain records cached, revalidation of a cached entry is not
possible, so not storing it is the only stance that keeps the stamps meaningful);
`DnsServer._reply` copies the bit verbatim (§3.2.2¶2's MUST). With CD clear and
anchors set, Bogus now *refuses*: a SERVFAIL carrying the never-serialised
`dnssec_bogus` marker (the EDE the walk collected can ride one reply OPT, so the
reason rides an attribute between the two halves of one recursive server) which
the serving side turns into RFC 8914 §4.7's EDE 6, the forged denial stays out
of the cache entirely (RFC 4035 §4.7's BAD cache is optional, and a cached bogus
denial would let the RFC 8020 cut launder one poisoned packet subtree-wide), and
the *failure* is noted — RFC 9520 §3.4 turned that into a MUST, riding the
existing §3.2 backoff, with `FailureEntry.dnssec` marking validation failures so
CD queries walk past them (§3.2.2¶5's "does not help the client") while every
other failure suppresses as before.

**Findings along the way**: (1) `DnsServer._flags_match` — its docstring has
listed "AD" among the must-agree flags since the MQTYPE round, while the line
itself read `dnssec_ok`, an inheritor of the old misnamed property: comparing
the request's OPT DO across combinations of one request is a tautology, and now
that the real bit exists the comparison means what its prose always said (an AD-
promising combination behind an unassertive primary is not merged). (2) RFC
9520 §3.4 really does upgrade §4.7's MAY — the first reading of "no BAD cache
implemented" looked like a gap until the update's own words appeared; the
failure note closes it with machinery that already existed. (3) the CD
lookup's `failures.forget` was silently unlocked on an unvalidated success —
forgetting is a recovery claim, and a CD walk cannot make one.

**Verified**: 1344 passed (+19 net: 4 wire bit-position/round-trip/old-stack
decode, 5 rewritten-or-new wiring refusals and AD-at-write/hit/cut pins, 2
validator Opt-Out `ad_worthy` tests over an `opt_out=` fixture knob, 4 serving
egress tests (CD copy, §5.8 gate both ways, EDE 6, plain-SERVFAIL negative), 1
MQTYPE AD-mismatch non-merge, 2 e2e tests (upstream bits disregarded, CD echo),
1 failure-flag test, 1 CLI print test), `ruff check`/`format` clean, `mypy
namespy` exits 0; `-O` run clean (the one standing cross-module-fixture warning
is unchanged).

**Next, in order**: (1) the positive half — judge terminal answers with
`validate_rrset` under the same fetch-loop, stamp `PositiveEntry.validated`, and
the §3.2.3 "if and only if" covers everything the rule names (the wildcard
answer's closer proof comes along with it); (2) the DS-strip question and the
`serve --dnssec` DO question remain open; (3) key-tag signalling (RFC 8145's
actual subject) now has a home: the helper queries know which zones they ask.

### Follow-up: the positive half — the answer, judged whole (RFC 4035 §3.2.3, §5.3.1, §5.3.4; RFC 4033 §5; RFC 9520 §3.4; RFC 5155 §9.2)

**Requested**: the first item of the previous "Next" — AD existed but could
only speak for denials; a validator whose NXDOMAINs are verified and whose A
records are not has answered half the question §3.2.3 asks.

**Delivered**: terminal answers run the same judge-fetch-stamp loop the denials
earned, with `_fetch_chain` generalized from a denial-specific function to a
judge-thunk runner (re-runs whole after every fetch: the one missing record may
unlock the verdict anywhere in the response). The judgment is a **composite**:
`_judge_answer` enumerates every distinct (owner, type) RRset the Answer and
Authority sections carry — §3.2.3's "all RRsets" is the claim AD makes, and
judging only the queried type could never license it — skipping DNSSEC types
(RRSIG is evidence, NSEC the denial's material) unless the client queried one
directly. Rank: Bogus poisons the whole response, Indeterminate defers it and
lends its hint to the loop, Insecure caps it, SECURE needs them all. The
verdict then behaves exactly as the negatives' did: refused with SERVFAIL + EDE
6 + the failure note when CD is clear, delivered raw and uncached when CD is
set, AD on the response and `validated` in the entry when fully verified, and
the cache-hit path asserts from the stamp for a validator and stays silent for
an anchorless reader.

**The conviction the half-crank could not see**: a zone the chain proves secure
answering **without** its RRSIG is now Bogus — RFC 4033 §5's missing-signature
rule, reached through `validate_rrset`'s unsigned path (zone stated, chain
secure). Before this increment the walk judged signatures only when they were
present, which is precisely the property the strip-a-signature attacker
selects: the downgraded answer would have been served as merely
unauthenticated, forever, with the resolver's own cache confirming it. The
stripping test (`test_an_answer_stripped_of_its_signature_is_bogus_not_unsigned`)
is the increment's reason to exist.

**The stamp's meaning narrowed, on purpose**: `validated` now means *fully
verified* — `ad_worthy`, not `secure`. The stamp answers two questions (may a
cache read assert AD; may a denial cut) and RFC 5155 §9.2¶1's Opt-Out refusal
reaches both, so an Opt-Out-rested denial no longer stamps at all: the check
that could not finish at write time is not allowed to be guessed finished at
read time, and the conservative reading costs only a re-walk. `PositiveEntry`
joined the same (already-migrated) SQLite column; `validate_rrset` surfaces
`WildcardAnswerProof.via_opt_out` — the third flag nsec.py exported and nobody
read (`via_opt_out` at 9.2, `DenialProof`'s, this one's) — so a wildcard
answer behind an Opt-Out next closer is secure, served, and unasserted.

**Findings along the way**: (1) `classify` needed no change at all — its
`Answer` fires terminal only when the alias chain lands on the real type, so a
response carrying CNAME+target arrives whole to the judge and both RRsets are
enumerated; an in-flight CNAME-only response yields no `Answer` and is judged
when its successor terminates. (2) ruff's B023 caught a real hygiene gap in
the answer thunk: `response` is a loop name; the denial thunk had grown its
defaults for `sec_zone`/`denial_rcode` but the answer one closed over
`response` and `sname.qtype` — bound explicitly, since "consumed this
iteration" is a property of the call site, not of the closure. (3) the
composite's reason string ("all 2 RRsets judged: …") is a test surface: the
event must say the response was judged as one thing, because that is the claim.

**Verified**: 1357 passed (+13 net: 9 positive-answer wiring tests — secure/AD/
stamp, cache-hit AD both readers, forged refused, stripped refused (the strip
attack), CD collect-everything-claim-nothing, silent-keys indeterminate,
proved-unsigned child insecure, no-anchors untouched; 1 two-RRset composite
with a poisoned SOA signature; 1 validator wildcard Opt-Out; 2 SQLite positive
round-trips), `ruff check`/`format` clean, `mypy namespy` exits 0, `-O` run
clean.

**Next, in order**: (1) the DS-strip question and the `serve --dnssec` DO
question remain open; (2) key-tag signalling (RFC 8145: `edns-key-tag` on the
helper DNSKEY queries, §4.2.2.1's two-list forwarding) now has an obvious
home; (3) aggressive NSEC caching (RFC 9908 — the denials now carry verdicts,
which is the precondition 9908 §5's caveats assume); (4) wildcard *synthesis*
from cache (roadmap §4's ⬜ row) can reuse the per-lookup store question
finally settled here.

### Follow-up: the two open questions, decided — DS at the strip, and who owes DO (RFC 4035 §3.1¶1, §3.2.1¶1, §4.1¶1; RFC 3225 §1¶3, §2¶1–¶5; RFC 8020 §2¶5)

**Requested**: the first item of the previous "Next" — two questions had been
carried open across several increments: whether §3.2.1's strip must withdraw
DS, and whether `serve` owes DO upstream regardless of the flag.

**Decided, DS**: yes, at the client hop. RFC 4035 §3.1¶1 enumerates what a
DO=1 query buys — "a security-aware authoritative name server for a signed
zone MUST include additional RRSIG, NSEC, **and DS** RRs" — and §3.2.1¶1's
exception is written in *types* ("MUST NOT strip any DNSSEC RR types that the
initiating query explicitly requested"), so DS is strip material unless the
query named it. The old exclusion was reasoned from the walk — referrals ride
DSes per §3.1.4 and must keep them — but the walk never *emits* a referral to
a client, and this is the one hop §3.2.1 addresses: `server._CLIENT_STRIP_TYPES`
adds DS for `_strip_dnssec` alone, `DNSSEC_SECURITY_TYPES` stays narrow for
judging and the walk, and the docstring now says one constant wearing both
coats was the mistake. 3225's own definition of "DNSSEC security RRs" (§1¶3:
SIG, KEY, NXT) could not have adjudicated a set RFC 4034 later redrew — the
4035 enumeration is the modern successor and it includes DS. The reachable
leak the decision closes: a DS arriving inside a non-authoritative upstream
answer the walk takes as given, headed for the clients §2¶3 reports "failing
(in the worst case)".

**Decided, DO**: `serve --dnssec` stays the operator's call, and the stance is
now stated at startup. §4.1¶1's MUST ("A security-aware resolver MUST include
an OPT pseudo-RR with the DO bit set when sending queries") speaks to the
resolver role, and `--validate` already implies the flag on that strength —
records never asked for are records never checked. Fetching DNSSEC octets on
every upstream query without validating anything is the trade RFC 3225 §2¶1–¶2
argued the DO bit into existence around, so off remains legitimate; what off
could not honestly do before was *say so*: `serve` now logs
`server_dnssec=validate|records|off` at startup, and `--dnssec`'s help names
the consequence for a DO=1 client — RFC 8020 §2¶5's echo is conditional on the
triggering query having asked, and this server *is* the triggering query.

**Verified**: 1359 passed, 1 skipped (+2 net: the old DS-survives pin rewritten
into three — DS stripped at DO=0 with the recount, a query naming DS keeps it,
a QTx naming DS keeps it), `ruff check`/`format` clean. Errata swept on 4035
before quoting §3.1¶1/§4.1: the two verified ones (§3.1.4.1's zone-cut DS
processing, §5.3.1's DNSKEY-try-each) touch neither sentence relied on.

**Next, in order**: (1) key-tag signalling (RFC 8145: `edns-key-tag` on the
helper DNSKEY queries, §4.2.2.1's two-list forwarding) now has an obvious
home; (2) aggressive NSEC caching (RFC 9908 — the denials now carry verdicts,
which is the precondition 9908 §5's caveats assume); (3) wildcard *synthesis*
from cache (roadmap §4's ⬜ row) can reuse the per-lookup store question
finally settled earlier.

### Follow-up: key-tag signalling — RFC 8145's option 14, played three ways (§4.1-§4.3, §7; RFC 4033 §2; RFC 4034 App. B)

**Requested**: the first item of the previous "Next" — the walk's helper DNSKEY
queries now know which zones they ask, and that knowledge is exactly what
`edns-key-tag` asks a querier to have.

**Read first, and it corrected an assumption**: §4's option is *telemetry*, not
a fetch directive — a signal of which KSKs the validator already pins so zone
operators can time a rollover (§7¶1). The subsetting mechanism people
misattribute to it is §5's Key Tag Query (the `#kt` QNAME scheme), a different
tool this increment deliberately does not build. §4.3 asks a responder for two
things only: it MAY log the tags, and §4.3¶2's MUST NOT forbids putting the
option in any response.

**Delivered**: the codec (`KEY_TAG_OPTION_CODE` 14, `key_tag_option`,
`key_tag_lists`, `key_tags_of`, `MAX_KEY_TAGS = 32` in `namespy/edns.py`) —
instances kept separate because §4.2.2.1¶2 transmits own and client lists as
"separate instances of the edns-key-tag option code", flattening reserved for
the copier's §4.2.2.2 reading; the cap taken seriously per §4.2.2.1¶3 with
§7¶3's "made up" tags as its reason. `Validator.key_tags_for(zone)` reads
exactly §4.2¶3's two admitted sources — anchors in either RFC 4033 §2 shape,
and DS records the descent collected — and nothing else, because §4.2¶6's MUST
NOT is not manners: a tag lifted from an answer's DNSKEY would put a forged
key's number into data an operator acts on. The walk then plays three roles:
**querier** — chain-fetch DNSKEYs carry the validator's own list (§4.2.2.1¶1),
DS fetches carry nothing (§4.2¶2, the option's only truly universal rule);
**copier** — a client's list rides the zone's own hop, as a second instance
behind a differing own list in the section's example order (§4.2.2.1¶2) or
alone when this server validates nothing (§4.2.2.2); **silent responder** —
reply OPTs are built from the response's own news, so §4.3¶2 holds by
construction. The plumbing gained `SendQuery.extra_edns_options` and a
per-request `client_key_tags` beside `client_cd`, extracted from the
initiating packet the same way.

**The hop gate (§4.2¶3's quiet requirement)**: the list is "the KSK(s) of the
zone *for which the server is authoritative*", and an iterative walk can point
at that server before the answer only where the queried name is the zone
itself — so the root routing a DNSKEY question for zone.test. carries no list,
and §7¶2 (listeners infer validators from lists) says why that restraint is
not fussiness. Refused on purpose: §4.2.2.1¶3's MAY to combine tags across
concurrent queries — it would make the server a store of who-knows-what, and
per-request copying is the only claim the document says a recursive resolver
owns.

**Findings along the way**: (1) inbound leniency decided against the module's
own FORMERR ledger — COOKIE and EDE have length rules *their documents* state;
8145 orders no rejection (§4.2¶7: "no action needs to be taken"), so a
malformed instance reads as no list rather than refusing a query nobody meant
to break — the reasoning recorded in `_edns_options_or_error`. (2) Two test
fakes monkeypatched onto `_send_for_entry` pinned its three-parameter shape;
the widened call surfaced them, and both were updated rather than the driver
compensated — the signature is the honest interface. (3) The
`entry.zone == sname.qname` gate means a DNSKEY query for a *non-apex* name
carries no list even at the zone hop — the walk does not know which zone will
answer authoritatively for such a name until it does, and guessing is the
"made up" error in a different costume.

**Verified**: 1376 passed, 1 skipped (+17 net, new `tests/test_edns_keytag.py`:
codec shapes and the §4.1 figure, cap, empty/out-of-range refusal,
instance-preservation and flattening, malformed-as-nothing, claims from
DS-anchors, DNSKEY-anchors, and descent-collected DS only, dedup, the copy
gate, two-instance forwarding and its identical-list collapse, helper lists
per zone with the DS query silent, packet extraction end-to-end, responder
silence), `ruff check`/`format` clean, `mypy namespy` exits 0.

**Next, in order**: (1) aggressive NSEC caching (RFC 9908 — the denials now
carry verdicts, which is the precondition 9908 §5's caveats assume);
(2) wildcard *synthesis* from cache (roadmap §4's ⬜ row) can reuse the
per-lookup store question finally settled earlier; (3) §5's Key Tag Query
(`#kt`) remains unbuilt — reachable now if a deployment ever wants subsetting
rather than signalling, and its §5.2 querier rules mirror what this round
already knows how to compute.

### Follow-up: aggressive NSEC caching — denials from cached proofs (RFC 8198 §5, App. A–B, §7, §9; RFC 9077 §3.4)

**First, a citation corrected**: the three "Next" lists before this one said
"aggressive NSEC caching (RFC 9908)". RFC 9908 is *Clarification and
Enhancement of the CSR Attributes Definition in RFC 7030* — certificate
enrollment, nothing to do with DNS. The feature the lists meant (and the
roadmap row at §6 always named correctly) is **RFC 8198**, *Aggressive Use of
DNSSEC-Validated Cache*, with its TTL rules as rewritten by **RFC 9077**. The
"§5 caveats" the lists referred to are RFC 8198 §5's own. The mis-citation was
caught by reading the document before implementing against it.

Shipped: `namespy/aggressive.py` (`synthesize_denial`) at the walk's
cache-lookup step (8198 App. A ¶3 places it there), the cache's second new
lookup (`DnsCache.denial_candidates`, both backends, documented fallback in
the base — a covering NSEC's owner is nobody's ancestor, so neither `get` nor
`nxdomain_at`'s walk can find it), the `aggressive_nsec` knob
(`RecursiveResolver`, `resolve_steps`, CLI `--aggressive-nsec`, default off),
and the `AggressiveDenial` trace event. The gates, each with its text in the
module docstring: the validated stamp is the entry's only test (App. B ¶2);
the bundle is re-run through the *full* response validators — §5.4 for NSEC,
§8.4–§8.7 for NSEC3 — against the queried name, so an incomplete proof falls
back to the network exactly as App. A ¶4's MUST says; an Opt-Out covering
record forbids synthesis (§5.2¶3); signatures count as well as TTLs (§7's
"until the effective TTLs or signatures expire"), read as a timestamp, never
re-verified — the stamp-at-write doctrine holds; the synthesised TTL is the
entry's remaining life capped at 10800 (§5.4¶2 as 9077 §3.4 replaced it, §9¶3
behind it); a CD client is never answered from synthesis (App. A ¶1); nothing
synthesised is ever written back.

Two things the reading caught that a sketch would have missed. (1) *Cross-cut
synthesis*: a parent zone's NSEC spans reach below its delegations with tidy
geometry, and answering from them would deny names the child zone may hold.
The hazard is already closed in the walks themselves — both closest-encloser
machines reject an NS-without-SOA or DNAME at the encloser (§8.3¶12, which is
8198 App. B ¶4 verbatim in intent) — and the one shape the response validators
never needed a guard for, NODATA synthesised from a *matching* record at a cut
name, gets the check in `_nodata_from`, with the exception the text demands:
DS is the one type the delegation point answers for (§5.4¶5, §8.6), so the
proven-unsigned answer is synthesisable and the TXT one is not. (2) *Two
clocks*: entry expiry runs on the cache's `time_fn` and signature windows on
UNIX seconds, and the fixture tree deliberately keeps them apart (1000.0
versus 1.8e9) — a `synthesize_denial` that re-checked `entry.expired(now)`
with the signature clock read every entry as expired and the bug surfaced as
"synthesis silently does nothing". The function now takes the caller-measured
`remaining` and leaves freshness to the backends, which forget expired rows
on read anyway; hoisting `clock = ...` out of the `if anchors:` branch fixed
the same conflation's twin (an aggressive walk without anchors used an
unbound variable — caught by the unvalidated-entry refusal test, which is
exactly the test that refuses synthesis and must still walk).

**Verified**: 1397 passed, 1 skipped (+21 net, new `tests/test_aggressive_nsec.py`:
neighbour NXDOMAIN and other-type NODATA with zero queries and no cache
growth, event order, unsigned entry, CD client, default off, foreign zone,
trace line; unit gates — stamp, signature epoch, cut refusals *and* the DS
exception, bitmap contradiction, TTL cap both directions, bare proof;
`denial_candidates` on both backends plus the `()` fallback; both CLI flag
polarities), `ruff check`/`format` clean, `mypy namespy` exits 0.

**A lesson the CI re-taught, twice**: the previous round's "CI green" was
wrong — run 41245125423 failed on the crypto-free ubuntu runner because
`test_the_walk_reads_the_initiating_packets_instances_into_one_copy` calls
the signed helpers without `@needs_tree` (local crypto masked it; the file's
other fifteen tree tests were marked). This round's push caught it, and the
fix commit `b205729` marks that test *and* re-cuts the new file: a
module-level skipif over-skips, so its two CLI tests and the base-cache
fallback are deliberately unmarked and run everywhere. Verified both ways
locally: full suite with crypto; with `cryptography` blocked, the two files
run their unmarked tests and skip the rest, nothing failing. Master is now
green on CI, Security, and Socket. The standing rule earns its keep:
**green means the CI run, not the local one** — `gh run list` after every
push, not after every test suite.

**Next, in order**: (1) wildcard *synthesis* from cache — 8198 §5.3's positive
half ("we revise this recommendation": a cache-deduced wildcard SHOULD answer
when the cache can prove the name would not exist without it — needs
`nsec_proves_wildcard_answer`/`nsec3_proves_wildcard_answer` fed from the same
`denial_candidates` scan plus the wildcard RRset itself, which the current
bundles do not carry: proofs hold NSEC/NSEC3+RRSIG only, so the write side
grows first); (2) the §4.5 row's other half — chain records in the cache
rather than per-lookup store — is the same data question viewed from
validate.py's side; (3) RFC 8145 §5's Key Tag Query (`#kt`) remains unbuilt
and optional.

### Follow-up: chain records enter the cache — the §5.2¶6 fetches have somewhere to land (RFC 4035 §4.5, §5.2¶6; TTL-and-signature unity per 8198 §7)

The validation-pipeline row's last clause was a door left open on purpose:
"chain records live in a per-lookup store rather than the cache ... revisit if
wildcard synthesis wants reused proofs." This is that revisit's first half —
the data plumbing, without the synthesis yet.

Shipped: a lookup whose verdict is secure files every DNSKEY and DS RRset it
saw as an atomic entry (RFC 4035 §4.5¶1 — the RRset with its covering RRSIGs,
min-TTL expiry, discarded whole), stamped `validated` because *this* resolver
verified those exact bytes end to end a moment ago; the hint loop in
`_fetch_chain` consults `cache.get(name, rtype, ...)` before its `SendQuery`,
and a stamped entry whose every signature still covers the moment feeds the
validator's store instead of the wire, traced as `ChainFromCache` — an
absence of a query is otherwise invisible. The ledger (`sec_material`, filled
in `_offer` beside the store) keeps what the store cannot: the store buckets
rdatas and drops the TTLs a cache entry must carry.

Three decisions the texts forced. (1) *The write gate is the secure verdict*:
bogus verdicts refuse to cache anything (§4.7's BAD-entry cache is the
optional one and this resolver does not exercise it), unvalidated walks never
reach the ledger, and an Insecure verdict's chain evidence is one signed
no-DS proof that already lives in its denial's bundle. (2) *The stamp
licenses the load, never the verdict*: unstamped DNSKEY material — a client's
own DNSKEY query having cached an answer — is refused as chain input because
this validator never verified it (§4.3's states are the validator's answers,
not the cache's), and even stamped material is re-verified signature-by-
signature against this resolver's anchors when the chain runs, as always.
(3) *Expiry is absence, never Bogus*: the signature-window read at load time
is the two-clock filter named last round — cache clock, signature clock —
and a stale cached key must send the walk back to the network (§9¶4's
poisoned-long-TTL row), not convict a live zone. A fresher stamped entry is
never aged out by a re-verification of the same bytes.

**Verified**: 1404 passed, 1 skipped (+7 net, new `tests/test_chain_cache.py`:
chain filed by a secure walk with atomic data+sig groups, second name in the
zone climbs the cache with zero helpers and three packets, unstamped material
refused, expired-signature-alive-TTL entry refused and re-fetched, bogus and
unvalidated walks file nothing, writer unit seam (min-TTL, fresher guard,
unsigned refusal), trace line), no existing test changed its expectation
except the aggressive round's `len(cache) == 1`, which chain entries
legitimately outgrew — rewritten to compare the baseline before and after the
synthesising walk. `ruff check`/`format` clean, `mypy namespy` exits 0.

**Next, in order**: (1) wildcard *synthesis* from cache (8198 §5.3, 4592) —
now nearly reachable: chain material crosses lookups, but proof bundles still
carry no wildcard RRsets, so the write side must start filing the template
(`*.encloser` owner — §4.5¶4's own sentence: "a security-aware recursive name
server could store this wildcard data and use it to generate positive
responses") before the serving side can deduce from it; the RRSIG Labels
field is the deduction (fewer labels than the expanded owner means
synthesised); (2) RFC 8145 §5's Key Tag Query (`#kt`) remains unbuilt and
optional; (3) then the non-DNSSEC rows in roadmap order — 7828/9210 TCP
keepalive, 8767 serve-stale (check the existing EDE 2/22 code first, the row
may predate it), 6841 0x20, 9824 compact digests, 10001 §4.2 families,
8509/9535 maintenance, 9364/9904/9905/9906 algorithm set, 5891/3492 IDNA,
9471 §3 — with the P4 experimental rows (DoT/DoH/DoQ forwarding, 9539 §4
opportunistic encryption) awaiting an explicit decline or a forwarding mode.

### Follow-up: the wildcard answers for names nobody asked about — §5.3's positive half (RFC 8198 §5.3; RFC 4035 §4.5¶4, §5.3.4; RFC 5155 §8.8; RFC 4592 §3.3.1, §4.1-§4.2)

Shipped: a validated wildcard-expanded answer files its template, and the
cache writes positive answers for other names through it. The write side
(`_cache_wildcard_template`, beside the chain writer) deduces the expansion
from the covering RRSIG's Labels field — §4.5¶4's own sentence named this
deduction — and rebuilds the signed name with the canonical helper
(`signed_owner_name`), storing the RRset at the wildcard's own owner, data
and signatures together, stamped and authoritative. SOA and NS never
template (RFC 4592 §4.1¶1 "can never be a source of synthesis"; §4.2¶3 leaves
wildcard NS undefined). The read side (`synthesize_wildcard`, with the
denials in `aggressive.py`, same `--aggressive-nsec` knob, orchestrated by
`synthesize`: denials first, wildcard after) enforces §5.3's two halves:
the template — deepest wildcard node with a cache entry, §3.3.1's "no
search for an alternate", a present-but-unusable entry means the network,
not the shallower wildcard — and the closer-match denial, the §5.3.4 / §8.8
proof run whole against a validated signature-live bundle from the
template's own zone.

Three things the design turned on. (1) The span proofs in §5.3.4/§8.8 are
thin — matching-QNAME refusal plus a covering span — and they are sound
cross-lookup only beside the same-zone rule: an NSEC(3) covering the NEXT
CLOSER proves every intervening name absent by tree closure, and a wildcard
above a zone cut cannot be the parent zone's signed data at all, so a cached
template's signer is its zone and the witnessing bundle must be that zone's.
(2) The wire packet, not the cached entry, is the write-side input: the
positive entry deliberately stores only the queried name's data (AD rides
the stamp), so the covering RRSIG has to be read where it still sits —
`response.answers`. (3) The two clocks again: served TTLs bounded by the
template's remaining life on the cache's clock, the template loadable only
while its signatures live on the signature's — and 9077 §3.4's three-hour
negative cap does NOT reach here: a synthesized positive is data, not
negative information.

**Verified**: 1420 passed, 1 skipped (+16 net, new
`tests/test_wildcard_synthesis.py`: judged-secure-and-filed, sibling
answered with zero queries, grandchild too (tree closure), TTL bounds,
no-template and no-denial fall back, off-by-default, CD exempt, unstamped
and expired-signature templates refused, forged answer files nothing and
refuses, denial-first ordering, AD down for anchorless readers, SOA/NS never
template, explicit answers never template, trace line). The fixture zone
grew its `*.y.zone.test.` TXT branch on the chain's wrap edge (y → *.y →
apex — canonical order preserved; every existing proof span unchanged —
verified by the 47 existing wiring/aggressive tests passing untouched apart
from the `_walk(aggressive=)` kwarg). `ruff check`/`format` clean,
`mypy namespy` exits 0. Roadmap: the wildcard row and the aggressive row's
remaining clause closed.

**Next, in order** (non-DNSSEC now — the aggressive pair is complete):
(1) 8767 serve-stale — check first whether the existing EDE 2/22 code means
the row predates implementation or the feature is genuinely unbuilt;
(2) 7828/9210 TCP connection reuse with edns-tcp-keepalive; (3) 6841 0x20
QNAME-case entropy; (4) 9824 compact NSEC3 digest RR types; (5) 10001 §4.2
address families; (6) 8509/9535 anchor maintenance; (7) 9364/9904/9905/9906
algorithm set; (8) 5891/3492 IDNA (P2 — the largest); (9) 9471 §3 referral
TC; (10) 8145 §5 #kt (optional); the P4 rows await a decline decision.

### Follow-up: serve-stale — expired data answers when the authorities don't (RFC 8767; EDE 2 per RFC 8914 §4.2)

The roadmap row said "roadmap P3" and nothing else; the EDE greps came back
empty of a feature (only the printer knew the code names), so this was
genuinely unbuilt, and it is now the third resiliency layer beside the
failure cache and the stamps.

Shipped, in the two layers §5 splits: the cache gains the maximum-stale
timer (`stale_ttl` on the base, both backends) -- an expired row inside the
window survives reads (`get` still says miss -- §7¶1 keeps the decision with
the resolver, never the storage) and `stale()` hands out exactly the
expired-but-in-window entry, retiring what the window has spent; the walk
consults that door at its two can't-refresh seams -- out-of-servers
exhaustion, and the RFC 9520 remembered-failure block (whose §5¶7 sentence
is the feature's own: inside the recheck window "the cache may be
immediately consulted for stale data"). The answer is assembled fresh:
§4¶4's MUST rewrites every record's TTL to greater-than-zero at the
recommended 30 (§6¶6's rate-limit reading -- and the records are REBUILT,
never edited, the entry keeps its originals), AD never rides (the stamp
says *verified then*; §3.2.3's claim is present tense), and
`response.stale_answer` becomes EDE 2 the way `dnssec_bogus` becomes EDE 6.

Decisions the texts left open, taken with their numbers: data-level failures
(alias loops, hop budgets) and validation refusals do NOT serve stale --
§6¶9's MAY extends to unreachable authorities, not to a name whose fresh
data just proved bad; CD clients DO (a cache read is not the inference
Appendix A exempts, and §9¶2's "for all clients" stands); all-Refused does
not preempt serving (§6¶11's open question -- treat it like every other
failure to refresh); retention equals usability (one knob, §5¶11's own
sentence); default off with `--serve-stale [SECONDS]` (bare = 86400, the
low end of the recommended 1-3 days).

Found en route, separate commit: the fuzz property replayed a genuine
counterexample -- an RRSIG whose signature field is empty raised the
constructor's bare `ValueError` through `parse_from`, escaping the parser's
one exception class; `DnsRecord.parse` now converts codec `ValueError`s to
`DnsPacketParseError` at the boundary (DNSKEY/DS/NSEC3's constructor
invariants cross the same door and are covered by the same conversion),
with the counterexample pinned as a regression test.

**Verified**: 1439 passed, 1 skipped (+19 net: `tests/test_serve_stale.py`
17 -- retention/refusal/retirement per backend, both walk seams, knob-off
honest failure, past-window gone, CD served, never AD even stamped, TTL
bounds, originals untouched, trace line, resolver-opens-cache-window;
test_dnssec_serving.py EDE-2 test +1; test_fuzz_wire.py regression +1). One init-ordering bug
caught by mypy (the cache-window block referenced `self.cache` before its
assignment -- moved after, pinned by the window test through
`RecursiveResolver(serve_stale=...)`). `ruff`/`format`/`mypy` clean.
Roadmap: the 8767 row to done.

**Next, in order**: (1) 7828/9210 TCP connection reuse with the
`edns-tcp-keepalive` idle timeout; (2) 6841 0x20 QNAME-case entropy;
(3) 9824 compact NSEC3 digest RR types; (4) 10001 §4.2 address families;
(5) 8509/9535 anchor maintenance; (6) 9364/9904/9905/9906 algorithm set;
(7) 5891/3492 IDNA (P2 -- the largest); (8) 9471 §3 referral TC; (9) 8145 §5
#kt (optional); the P4 rows await a decline decision.

### Follow-up: the stub resolver — the forwarding mode the encrypted transports were waiting for (RFC 1034 §5.3.1, RFC 1035 §4.1.1)

A scope decision, from the user, reorders this roadmap: the DoT/DoH row was
parked as "P4, no forwarding mode to put them behind" -- and the answer given
when the loop reached that fork was that the parking was always temporary:
"we most certainly do want to implement Stub Resolvers for DoH/DoT." So the
prerequisite lands first, and the encrypted transports become the head of the
list.

Shipped (increment A of that track -- Do53 forwarding): `namespy/stub.py`,
two objects. `Upstream(host, port, transport)`: an address literal (the stub
resolves nothing, its bootstrap servers least of all), `parse` reading the
configuration-text forms (`1.0.0.1`, `1.0.0.1:5353`,
`[2606:4700:4700::1001]:853`), transport validated against `TRANSPORTS` at
the door so a typo is a startup sentence. `StubResolver(Resolver)`: drives
the walk's *own* send path at the configured server -- RD set (§4.1.1's "di-
rects the name server to pursue the query recursively"), answer returned
exactly as it arrived. The semantics the texts leave to be taken: **REFUSED
is this upstream declining the arrangement** (§4.1.1's "Recursive query
support is optional", §5.3.1¶2's warning to verify the servers will do the
service) -- the next is asked, an all-refused list returns the refusal;
**SERVFAIL is an answer** -- the upstream did the work, fanning out buys
delay not news; **CD copies** (§3.2.2's arrangement) via `client_cd`.

The enabling refactor, and the one risk taken: `Resolver.query` already
carried UDP-with-TCP-fallback and answer matching, but the *receive* plumbing
it assumes (`connection_made`, `datagram_received`, the v6 bring-up) lived on
`RecursiveResolver`. Those four methods moved to the base -- behavior-
identical for the walk (1400-odd tests, one `TcpStub` signature updated for
the new `port` kwarg), inherited by the stub -- and `query()` gained `port`
(default 53, the walk untouched) and `force_tcp` (the caller's transport
choice, not an inferred fallback). One socket engine, whoever is asking.

CLI: `--forward UPSTREAM` (repeatable, tried in order), `--stub-transport
udp|tcp`, composed SERVFAIL (RA set) when nobody speaks, `--serve` and
`--mqtype` conflicts said plainly; `+forward` is not a dig token and none was
invented.

**Verified**: 1457 passed, 1 skipped (+18 net: `tests/test_stub_resolver.py`
13 -- parse/validate/normalize, RD-on-wire, answer-intact passthrough, custom
port, CD copy, rd=False, REFUSED-failover in order, all-refused, SERVFAIL
passthrough with no fan-out, silence to None, tcp-transport-first without
touching UDP; `test_cli.py` +5 -- timeout said not thrown, forwarded answer
printed with the configured port, hostname-upstream refusal before any
socket, two conflict errors). `ruff`/`format`/`mypy` clean.

**Next, in order** (the transports, as requested): (1) **DoT** (RFC 7858) --
`transport="dot"`, default port 853, stdlib `ssl` (`asyncio.open_connection
(ssl=...)`), §5's server-name authentication (the `Upstream` needs a
`server_name` once hostnames re-enter at the TLS layer), the 2-octet framing
`_query_tcp` already speaks, and 7828's idle timeout while at it; (2) **DoH**
(RFC 8484) -- `application/dns-message` POST/GET, HTTP/2 decided honestly
(stdlib socket work or an optional extra in the `cryptography` pattern);
(3) the rows from the earlier list as they fit -- 7828/9210 TCP reuse is now
part of (1), then 6841, 9824, 10001, 8509/9535, 9364/9904/9905/9906, IDNA,
9471, 8145 §5; 9539 §4 opportunistic encryption reuses the same transports
pointed at the authority leg, later than the stub's use of them.

### Follow-up: DNS over TLS for the stub, paced by edns-tcp-keepalive (RFC 7858, RFC 7828)

Increment B of the stub track. `--stub-transport dot` (or an
`Upstream(transport="dot")`) now forwards over TLS, and the connection it
opens is a *session*: held across queries, paced by the keepalive option,
remembered when it fails.

Shipped: `Upstream` gains `transport="dot"` (default port 853 per §3.1¶1,
with §3.1¶2's "MUST NOT be port 53" respected by construction -- TLS is
chosen by transport name, never guessed onto 53) and `server_name`, the
identity the certificate must answer to, written `1.2.3.4:853#dns.example`.
Authentication is the door, not a knob: this build declines §4.1's
unauthenticated profile outright (privacy without identity on an attackable
path feeds a stub any answer, and cleartext transports exist for operators
who mean that), so `dot` without a name is a startup sentence, and the
handshake rides `ssl.create_default_context` -- BCP195's posture -- through
the `_tls_context()` seam where an application adds its enterprise CA the
same way the tests add their generated cert.

Reuse is §3.4's: one `_Session` per upstream -- reader, writer, lock, idle
timer -- registered at connect, so a concurrent query waits on the session's
lock instead of opening a rival handshake (§3.3¶2's pipelining left
unexercised deliberately: one exchange at a time discharges §3.3¶3's
matching duty by ID alone, and a stub's tail latency belongs to its
client). The framing moved to the base as `_stream_exchange` -- the walk's
TCP fallback and the TLS sessions speak §3.3¶1's one-write length prefix
through the same code.

RFC 7828 gives the idle life: the empty request option (§3.2.1¶4's MUST,
`keepalive_option()`) rides every stream query; `keepalive_of()` reads the
response across 4-octet, draft-era 1-octet, empty and absent forms, keeping
0 distinct from None; `_idle_seconds` honours the offer, floors it at 2 s
(reuse renewed per-query is a handshake tax with none of the benefit),
defaults it to 30; TIMEOUT 0 closes now (§3.2.2¶3). §3.1¶4's memory:
handshake failures, refusals and timeouts remember an upstream for an hour
-- the paragraph's own example -- and `forward` skips it silently until the
deadline; a live answer clears the note, and a session that merely died
idle mid-queue re-opens invisibly with one retry.

**Verified**: 1471 passed, 1 skipped (+14: `tests/test_stub_dot.py` -- a
real TLS server on loopback with a `cryptography`-generated day-cert,
skip-gated on the extra: round-trip RD/intact over TLS, the empty option
observed server-side, sequential and concurrent reuse (connections == 1),
zero-closes/offered-held/floor-held/default-held, name mismatch fails
closed *and stays remembered* (no second SYN), 853 defaults, the full
option parse table). `ruff`/`format`/`mypy` clean. Roadmap: the 7858 row to
done; a new 7828/9210 row opened at 🟡 (stub transports done, walk TCP
reuse and server-side keepalive remain).

### Follow-up: DNS over HTTPS for the stub, in whichever HTTP the server negotiates (RFC 8484)

Increment C of the stub track. `--stub-transport doh` (or
`Upstream(transport="doh")`) forwards over HTTPS, and the honest
HTTP/2-versus-stdlib question from increment B's next-list is now answered:
an optional extra (`h2`, the pure-Python one, in the new `[doh]` extra) for
the HTTP/2 half, and a stdlib HTTP/1.1 client for the fallback §5.2¶2
allows -- so the extra accelerates the transport and is never required by
it.

Shipped: `namespy/doh.py` -- `_DohSession` owns the shared shape (the
`exchange` that parses the body and refuses anything but a 200
`application/dns-message` answering the questions asked, §4.2.1; the lock
the serial transports need), and two subclasses own the HTTP:
`_Http2Session` multiplexes one query per stream over a single held
connection (§4.2¶3's multi-streaming -- the reason the h2 half exists),
with the flow-control bookkeeping that makes a DNSSEC-sized answer
deliverable: SETTINGS widens the per-stream window to 1 MiB, the
connection window gets an explicit WINDOW_UPDATE (RFC 7540 §6.9.2 --
SETTINGS alone is per-stream only, and a waiting reader would deadlock at
65535 bytes), DATA is acknowledged as it buffers, and responses and
requests are chunked to the peer's `max_frame_size`. `Http1Session` speaks
one-request-at-a-time keep-alive, conservatively idled at 30 s by a timer
(§5.2's http/1.1 has no keepalive option of its own, and RFC 7828's does
not travel on HTTP), serialised by the base's lock. The GET form fills
§4.1's `{?dns}` template with base64url-no-padding (§4.1.1¶5's own encoded
message is a golden test); POST carries the §4 wire bytes with the §4.1.1
content-type. Every query leaves with ID 0 (§4.1¶8, HTTP correlates) --
`_ask_stream` zeroes it for DoH sessions only, and `questions_echo` is the
matching guard: the HTTP pair is what matches a reply to a question, so
the questions themselves must.

Stub-side, the dot machinery generalised rather than duplicated:
`_ask_dot` became `_ask_stream`, `_dot_dead` became `_stream_dead`,
`_stream_connect` dispatches dot-or-doh, and the session loop has one new
branch -- a multiplexed session (h2) skips the serial lock, every other
session still takes it. `Upstream` gains `path` (`#<name>/<path>`, the
§3¶1 configured template; the default `/dns-query`) and doh's default port
443 (§2.1); `Upstream.parse` now takes the declared transport, because
`dataclasses.replace` after parse re-ran `__post_init__` with the port the
*udp* default had already pinned -- `--stub-transport dot` had been
quietly forwarding to 53 (a bug the dot increment shipped and this one
closes, with a test naming it). Authentication is unchanged in kind: §8.1¶1
says the server MUST be authenticated, so doh enters through
`_tls_context`'s BCP195 door with `doh_alpn` adding §5.2's `h2, http/1.1`
offer, and a doh upstream with no `#<name>` is a startup sentence.

**Verified**: 1488 passed, 1 skipped (+17: `tests/test_stub_doh.py` -- real
TLS servers on loopback, ALPN-decided: POST/headers/ID-0 observed server-side,
sequential reuse and three-way concurrent multiplexing on one connection
(connections == 1), a 90 KB answer proving the window bookkeeping, the
http/1.1 round-trip + reuse + idle-timer, GET with the RFC's base64url
golden vector, 400/foreign-media/foreign-question all refused to None, the
dead-upstream memory, path/port parsing). `ruff`/`format`/`mypy` clean.
CI: the extras job now installs and exercises `[crypto,doh]` together.
Roadmap: the 8484 row to done.

**Next, in order**: (1) the 7828 row's remaining halves -- reuse for the
*walk's* own TCP fallbacks, the server-side of keepalive; (2) the earlier
list as it fits -- 6841, 9824, 10001, 8509/9535, 9364/9904/9905/9906, IDNA,
9471, 8145 §5; 9539 §4 reuses these three transports on the authority leg,
later. DoQ (9250) stays deferred: no stdlib QUIC, and an extra sized like
`aioquic` is a bigger conversation than `h2` was.

### Follow-up: the walk holds its streams, and the demo server answers on TCP (RFC 7766 §6.2, RFC 7828 §3.3, BCP 235)

Increment D of the transport track, the last two halves of the
7828/9210 row. The client side stopped treating a TCP fallback as a
one-use tissue, and the server side grew the stream front it never had.

Shipped, client: `Resolver._query_tcp` -- shared by the walk's
truncation/timeout retries and the stub's cleartext upstreams -- pools one
`_Session` per `(host, port)`: reuse per RFC 7766 §6.2.1¶1, one connection
per server with a second query waiting on the session's lock rather than
opening a rival line (§6.2.2¶1's MUST to minimise), the server's offered
keepalive TIMEOUT arming the idle timer on every answer (§3.2.2¶2's
"override any previous timeout ... close before it expires"), 0 dropping
the session on the spot (¶3), absence riding the 30 s default (¶4's return
to RFC 7766, held as a promise this client can keep). A stream that died
between queries -- the server's own idle policy, ordinary and expected --
is reopened silently with one retry (§6.2.4¶2); a *mismatched answer* on a
shared stream also retires the stream, because a stale response is the
reading position drifting. Pipelining stays unexercised deliberately, the
stub's stated reason: one exchange in flight discharges §6.2.1¶2's
no-reused-ID duty by construction. `AXFR` is §6.2.2¶1's named exception --
one-shot, never pooled. `_Session`, `_idle_seconds` and the two keepalive
constants moved to `resolver.py` beside the base transport that now shares
them (stub re-exports so its tests import the same names);
`_close_tcp_sessions` hooks both `aclose` paths.

Shipped, server: `DnsStreamServer`, one protocol instance per accepted
connection in front of the shared `DnsServer` (one responder pipeline, one
lookup semaphore, two transports -- the `StreamChannel` send-seam threads
`channel=` through `respond_to_packet`/`_reply`/`_error`/`_apply_edns` and
the datagram path never sees it). Framing per RFC 1035 §4.2.2 with the
idle clock reset only by a *complete* message (§7766 §6.2.3¶3's slow-read
warning); pipelined queries processed concurrently but answered through
an ordered outbox so responses leave in arrival order (§6.2.1.1¶4's MUST
to expect and SHOULD to process). The keepalive answer:
`keepalive_option(timeout)` gained the server form (§3.1's two-octet
TIMEOUT), and the front advertises exactly `DnsServer(tcp_idle=...)` --
the default 30, or the operator's number, never a second one (§3.3.2¶1's
MUST ties advertisement to enforcement); `tcp_idle=None` answers with no
option at all and clients fall back per §3.2.2¶4; 0 says so and ends the
line after flushing; a client's own TIMEOUT-0 hint (not the finished
client form, §3.2.1¶4, but the intent such bytes can only carry) gets its
answer advertised at 0 and closes the line -- advertising thirty from a
connection about to end is the one sentence §3.3.2¶1 forbids. A query
with no OPT and so no option (RFC 6891 §7, quoted by §3.4¶6); a
UDP query carrying the option is ignored (§3.3.1¶1's MUST, pinned by
test). Parse failures answer FORMERR with no OPT and spare the stream;
the zero-length frame ends it (no specification dictates that one --
the comment says so rather than citing an invented clause; a message of
zero octets describes no reading position to continue from). `--serve`
now binds TCP beside UDP: BCP 235 (RFC 9210 §3) updated RFC 1123's
"SHOULD support TCP" to "All DNS resolvers and servers MUST support and
service both", so a demo server answering only UDP would be
demonstrating the exact failure that document catalogues.

**Verified**: 1508 passed, 1 skipped (+20: `tests/test_stream_reuse.py`
-- 8 against a real framed TCP server: two forwards one connection, three
concurrent one connection, offered-timeout holds, 0 refuses and the next
ask needs a fresh line, die-between-queries reopens with no error
surfaced, mismatched IDs discredit the stream, AXFR never pooled, close
really closes; `tests/test_server_stream.py` -- 12 on real sockets: the
default 30 advertised, tcp_idle=17 advertised as 17, silence silent but
OPT still present, unextended queries unextended back, tcp_idle=0
advertises 0 and EOFs, the client's 0-hint answered at 0 then EOF,
FORMERR-spare-the-stream, zero-length-dies, the 1-second idle close
timed from the last message, pipelined concurrency measured (<0.14 s for
two 0.08 s walks) and ordering checked, UDP's MUST-ignore, and the
package's own `StubResolver(transport="tcp")` against its own
`DnsStreamServer` agreeing on eleven seconds over one accepted connection).
`ruff`/`format`/`mypy` clean, `-O` run holds, coverage 91%. CI: the serve
tests grew the `_stub_stream_listener` seam (the listener is the fourth
socket serve must let go, and the leak test now proves it). Roadmap: the
7828/9210 row to done.

**Next, in order**: (1) the earlier list as it fits -- 6841, 9824, 10001,
8509/9535, 9364/9904/9905/9906, IDNA, 9471, 8145 §5; (2) 9539 §4
opportunistic encryption now reuses all four transports on the authority
leg -- the transports it needs have all landed, so the row is purely the
probe, the store, and the fallback; (3) DoQ (9250) stays deferred on the
`aioquic`-sized conversation.

### Follow-up: the walker encrypts its own authority leg when the server will (RFC 9539 §4)

Increment E of the transport track: the row whose turn the last two
increments were announced to serve. `--dot-authority` (and
`RecursiveResolver(opportunistic_dot=True)`) makes the walk try DNS over
TLS to port 853 of every authoritative address, remember the verdict, and
choose transports from the memory -- the document's own "bolt-on" shape
(§4.3¶4), with the policy extracted whole into
`namespy/opportunistic.py`: Table 2's per-(transport, IP) record and
Table 1's parameters (persistence 3 d, damping 1 d, timeout 4 s,
per-protocol per errata 7831/7832 -- both verified errata applied and
cited at the formulas they fix), and §4.6's decision functions
(`send_over_do53`, `may_initiate`, `consider`, the note_* transitions of
§4.6.4-6.7) as pure (state, now, params) arithmetic, 100% covered without
a socket.

The hands live in `resolver.py`. `query()`'s cleartext ladder moved,
unchanged, into `_query_do53`; `_query_authority` now consults the table
first: established session rides alone, fresh success (the §4.6.1¶2
bullets) speaks only encrypted with §4.6.5's one-line cleartext fallback
when the leg fails, nothing-remembered races Do53 against a fresh
initiation, and *the losing encrypted initiation keeps running* --
§4.6¶5's explicit unlike-Happy-Eyeballs clause ("continued to establish
whether the IP address X is capable"), its verdict landing in the table
via a strong-referenced learning set whose done-callback both retires the
task and consumes its exception. The RFC's "already processed" marking
(§4.6.2¶4-¶5, §4.6.9¶7-¶8) is emergent, not bookkept: the winner pops the
pending key, so the loser's late answer finds no slot -- machinery that
predated the RFC discharging its instruction. The DoT leg is the same
`_Session`/`_stream_exchange` machinery as the pool, under a per-host
lock (one initiation, one exchange at a time; §4.6.8.2's pipeline MUST
applies only when multiplexing, which this is not), and its TLS posture
is the deliberate inverse of the stub's: `CERT_NONE` because §4.6.3.4's
MUST to accept any certificate rests on the downgrade argument (rejecting
forces cleartext, and a forced fallback is the leak), no
`server_hostname` because §4.6.3.3¶4 says the SNI would be the wire's
clue which query the walk is walking (the stub verifies strictly
*because* its operator chose that server -- both stances are cited at
their doors so nobody "fixes" one into the other), ALPN `"dot"` offered
per §4.4¶2's MUST and -- per 7858/9539 containing no ALPN-result
rejection clause, verified by grep -- offered as a target, not enforced
as a veto. Failure taxonomy: refusal/alert → §4.6.5 fail-damp; handshake
stall → §4.6.3¶4 timeout-damp; EOF on a ride → §4.6.7 close-no-damp
("retry promptly" is what status SUCCESS buys); stall-mid-exchange →
§4.6.6 fail-damp (an authority that takes queries then goes silent is
§4.2¶4's accidental delay, damped away); mismatch or garbage → desynced
stream, fail-damp, same reading-position argument as the cleartext pool.
§7828 rides the same leg: an authority's keepalive TIMEOUT arms the
session, a 0 retires it blamelessly (the §4.6.7 shape again).

Deferred, each cited in the module docstring: DoQ (§4.4's second SHOULD,
`aioquic` again), resumption (§4.6.3.2 -- asyncio's client exposes no
ticket-presenting seam, so Table 2's `resumptions` field stays honestly
empty; early data §4.6.3.1 is conditional on exactly that seam), padding
(§4.6.8.1 → the 8145 §5 row), restart persistence (§4.5¶7 is vacuous for
a library object), and the row's SVCB half: the `_dns.<name>` discovery
is RFC 9461 §4 policy (alpn-absent means incompatible, port is
auto-mandatory) over codecs that already exist -- the next increment,
which turns this row 🟡 to ✅. Flag refused with `--forward` (a stub has
no authority leg); default off (§4.1¶1's OPTIONAL, plus new egress).

**Verified**: 1529 passed, 1 skipped (+21: `tests/test_opportunistic.py`
-- 8 pure-policy tests walking §4.6.1/§4.6.3/§4.6.4-6.7 clause by clause
including both errata proven *as* per-protocol formulas (two
ProbeParams, two verdicts), and 13 live tests against the DoT fixture --
race both-go/encryption-wins, success silences cleartext on the next
query (one connection, counted server-side), **SNI absent and ALPN
"dot" negotiated proven from the server's own `ssl_object`** (the only
witness that could), self-signed certificate accepted because §4.6.3.4
says so, closed-port fallback + damping, stalled-handshake learning
continuation (settle-then-assert), §4.6.7 stream-kill → cleartext
carries that one query → prompt retry over a fresh connection,
mismatched and malformed answers discredit their streams, keepalive 0
retires blamelessly, force_tcp outranks the policy, `aclose` closes the
encrypted streams, and the §4.6.6 stall damps). Two test-harness lessons
are written into the file: a DoT fixture's `wait_closed()` deadlocks with
an undisposed client in the same loop (hence `dispose()`), and Windows
loopback black-holes refused ports rather than RST-ing them, so
"refused" asserts fail-*or*-timeout -- the two §4.6.3¶6 gates that retry
identically. `ruff`/`format`/`mypy` clean, coverage 91%
(`opportunistic.py` 100%). Roadmap: the 9539 row ⬜ → 🟡, naming the
SVCB half as what remains.

**Next, in order**: (1) the `_dns.<name>` SVCB discovery over the landed
9461 codecs -- port, alpn, policy from the answer -- completing the row;
(2) the earlier list as it fits -- 6841, 9824, 10001, 8509/9535,
9364/9904/9905/9906, IDNA, 9471, 8145 §5 (padding would serve both this
leg and 7858); (3) DoQ (9250) stays deferred on the `aioquic`-sized
conversation, blocking §4.4's second SHOULD and this row's third
transport.

### Follow-up: the walker asks the authority where its TLS lives (RFC 9461)

Increment F, completing the transport track's last row: the SVCB
discovery that upgrades RFC 9539's blind probe. `--dot-authority` now
resolves `SVCB` at `_dns.<NS name>` (Port Prefix Naming, 9461 §3, with
§3.1's `_9953._dns....` form constructed too) before its first TLS
attempt to an address, and probes the port the answer names -- §4.2¶1's
853 when the record states none.

`learn_dot_endpoint` in `namespy/opportunistic.py` is the whole §9460 §3
procedure over a supplied fetch callable -- selection through the
existing `select_records(client_alpn=(b"dot",))`, capped AliasMode
following (§2.4.2¶10's MUST: five hops, with the spec's own
`_dns.ns.example -> _dns.ns.nic.example` example as a test), then
§9461 §4's policy per candidate: alpn must carry `dot` (§4.1); an
explicit `port` is honored unless it appears on the confusion-risk list
-- which is where a copied citation and an understood one diverge, and
this one was re-derived: the first cut was a two-port allowlist that
rejected 9461's *own §7 example port 8530*, so the rule is now FETCH
§2.9's bad-ports enumeration (fetched from the living standard, 83
numbers) with 443 argued back in (FETCH blocks it as a browser HTTP
alternative; 9461 §4.2¶1 names it DoH's default, and TLS bytes belong at
a TLS port) and 53 left out (encrypted bytes at a cleartext server is
this whole document's confusion); a foreign TargetName survives only when
an ipv4/ipv6hint vouches for the very address being probed (§4.3, §6¶3's
self-target steer); root targets mean the binding itself (§2.5). The
verdict memo lives on RecursiveResolver keyed by **(name, address)** --
§9539 §4.2's per-IP discipline applied to discovery, because a hints
verdict about one address of a multihomed NS says nothing about
another -- sized by the answer's minimum TTL clamped to [60, 86400],
misses remembered five minutes so a silent authority costs one walk and
not one per query.

Two standing rules of the composition are worth the reason, not just the
rule. **Discovery never vetoes:** every unusable outcome -- NODATA,
incompatible, alias exhaustion -- retargets the probe to blind 853
rather than silencing encryption, because the record arrives over the
very channel it describes (§6¶2's first bullet concedes this explicitly)
and a forged answer must not be able to force cleartext; only the
handshake itself proves a port. And **the discovery walk bootstraps over
cleartext:** a guard flag (`_dot_discovering`) bows the §4.6 hook out of
the way for its duration, which both bounds the recursion (a nested
opportunistic probe would spawn its own discovery, whose walk spawns
...) and forecloses a concrete deadlock -- the `_dns` name is served by
the very authority whose lock the initiating leg holds while it asks.
The flag's conservative direction -- a concurrent unrelated query may
ride cleartext for the length of one discovery -- costs only a slower
exchange, never a wrong one. The port question moved to where it belongs
for all this: inside `_dot_query`'s initiate branch, under the host lock
and after the table has said *initiate* -- a riding query never pays for
a discovery walk, and a test (`endpoint_asks`) pins that the seam is
consulted exactly once per fresh session.

**Verified**: 1550 passed, 1 skipped (+21: 15 pure-policy -- default and
explicit ports honored, 6667 declined whole-record, DoH-only records
incompatible, foreign targets gated on hints, priority order walked
past a bad first choice, the spec's alias example followed once, loops
capped, TTL taken smallest, unparseable RDATA ignored, root-alias
silence, naming validation -- and 6 seam tests on a page-table
RecursiveResolver: memoized hit and miss, per-address keying, the
discover=False knob, mid-walk re-entry answered blind without a second
walk, plus the socket-level proof that a discovered port outranks a
confirmed-dead blind one). Two real findings on the way: `labels()`
yields wire bytes, so `str(label)` was comparing `b"'_dns'"` forever
(until a shared `_label_text` decoder said so in one place), and the
allowlist-versus-FETCH-list mistake above, caught by a test written from
the spec's own example rather than from the implementation.
`ruff`/`format`/`mypy` clean, coverage 91.25% (opportunistic.py 94%).
Roadmap: the 9539/9460/9461 row 🟡 → ✅, with DoQ, resumption, and
padding left as the cited carve-outs.

**Next, in order**: (1) the earlier list as it fits -- 6841, 9824, 10001,
8509/9535, 9364/9904/9905/9906, IDNA, 9471, 8145 §5 (padding would serve
the opportunistic leg and 7858 alike); (2) DoQ (9250) stays deferred on
the `aioquic`-sized conversation -- it is now the only missing transport
in three documents' worth of transport rows, and it would ride the same
probe table as a second E; (3) the authority leg's DoH answer (a
dohpath-bearing `_dns` record is already parsed and declined -- wiring
`namespy/doh.py` to the same seam is the small remainder when wanted).

### Follow-up: the boundary that used to be the caller's job — IDNA2008 (RFC 3492, RFC 5891, RFC 5890 §2.3)

Increment G, the first item off the earlier list and the roadmap's one
remaining *correctness* gap ("callers must pre-encode today"):
`namespy/idna.py`, with `DomainName.from_unicode` and the CLI's two
query entry points as the boundary. `namespy münchen.de` now works.

The codec is a line-by-line transcription of RFC 3492 §6.1-§6.3 with §5's
parameters, and the tests read like the document: all eighteen §7.1
sample strings pinned encode-and-decode (§6.2¶4: one encoding per
sequence, so both directions must agree with the spec's own bytes), the
§7.2 traces checking §6.1's bias checkpoints (21 … 84 … 90) and example
L's insertion-order lesson, example S pinning the
delimiter-after-literals rule at the codec level where it lives. The
decoder distinguishes §6.2's failures by name -- unexpected end of input,
no-digit-value, non-basic literal -- because §6.2¶3 makes that taxonomy
the argument that no two inputs decode alike. Overflow is §6.4¶2's
`B > maxint − A (div C)` arithmetic against a 26-bit maxint: §6.4¶1's own
bound for IDNA labels, chosen because erratum 265 redefines maxint as
"the maximum value of an integer variable" and Python has none -- the
guard exists for inputs that are *not* valid labels.

Above the codec, the label protocol is RFC 5891 §4/§5 as refined by the
5890 §2.3 taxonomy. Three decisions carry reasons worth keeping. **Case
has three answers, not one:** the decoder reads digits in any case (§5¶6),
the encoder emits them lowercase (§5¶6 + RFC 5890 §2.3.1¶4 "A-labels
should be produced only in lowercase"), and the *fold* a lookup
application may apply first is ASCII-only -- `str.lower()` can grow a
label (U+0130 becomes two characters), so `_fold_ascii_case` moves A-Z
and nothing else, which is also the DNS's own equivalence (§2.3.2.4) and
this package's identity convention. The distinction is load-bearing:
`MÜNCHEN` folds to the label for `mÜnchen` (`xn--mnchen-psa`), *not* to
`münchen` (`xn--mnchen-3ya`) -- a test pins it. IDNA2008 itself maps
nothing (its founding departure from 2003, appendix A), so a U-label
containing A-Z is rejected outright (the RFC 5892 tables put A-Z in
DISALLOWED anyway) and `map_ascii_case=False` gets the strict reading.
**The tables are a stated deferral, not a silent one:** RFC 5892's
derived character sets ship nowhere in a standard-library package, so the
tests run as far as `unicodedata` decides -- `Cn` unassigned (against
*this Python's* Unicode, which is exactly §5.4¶9's semantics), controls,
separators, private use -- and CONTEXTJ/CONTEXTO go to §5.4¶13's "rely
on the presence or absence of labels in the DNS", which is what a lookup
application owes anyway; declining to process a rule-conforming string
would be the actual non-conformance. **Zone data cannot throw:** an
A-label typed by a human is a question and gets rejected with a sentence
when fake (§5.3¶1's round-trip test -- decode, run §5.4, re-encode, must
be identical), but `to_unicode` is presentation, and §5.3¶2 asks of a
broken label only that it be recognized as not-one; it comes back
lowercased as written rather than raising.

Two findings on the way, both kept as tests. The first scratch run of the
overflow guard used `z`s -- but `z` is digit-value 25, which *breaks*
every delta run against t=26, so `"z"*10` is not an overflow: it decodes
cleanly, into four CJK code points, and is instead the cleanest
demonstration of §6.2¶4's bijection (re-encoding reproduces it exactly);
the overflow test uses 9's (value 35, never below any t). The second:
an append to the growing module silently replaced `_adapt`'s `return`
with the next function -- the vector tests caught it on first run, which
is why the vectors went in before anything depended on them.

**Verified**: 1628 passed, 1 skipped (+78: the §7.1 vectors both
directions, §6.2/6.4 failure modes and the surrogate gate, §7.2 trace
checkpoints and the bijection, the U-label rejection matrix, known
answers `xn--mnchen-3ya`/`xn--bcher-kva` from the zones themselves,
Fake-A-label rejections, presentation pass-through, and the
from_unicode/CLI integration including its one-sentence SystemExit).
`ruff`/`format`/`mypy` clean, coverage 91.3% (idna.py 94%; the uncovered
lines are defense-in-depth guards -- encode-side overflow, the round-trip
check -- that the other guards make unreachable, cited as such). Roadmap:
§7 "Names beyond ASCII" row ⬜ → ✅, and the priority table finally
caught up with the feature tables -- IDNA, wildcard synthesis (4592),
DNSSEC validation, serve-stale (8767) and walk-side TCP reuse
(7828/9210) are struck through as the shipped rows they have been since
increment D.

**Next, in order**: (1) the earlier list as it fits, IDNA now off it --
6841, 9824, 10001, 8509/9535, 9364/9904/9905/9906, 9471, 8145 §5
(padding would serve the opportunistic leg and 7858 alike); (2) DoQ
(9250) stays deferred on the `aioquic`-sized conversation -- still the
only missing transport in three documents' worth of transport rows, and
it would ride the same probe table as a second E; (3) the authority
leg's DoH answer (a dohpath-bearing `_dns` record is already parsed and
declined -- wiring `namespy/doh.py` to the same seam is the small
remainder when wanted).

### Follow-up: the denial that denies the name — RFC 9824, and the citation audit that preceded it

The deferred-work list said "6841" first. It should not have been trusted at
all. Before choosing increment H, every remaining row's citation was re-opened
against the corpus itself (roadmap row 194's standing obligation, four months
overdue), and the audit found three wrong pointers, two of them naming
documents unrelated to the feature they justified. The first: **RFC 6841 is
"A Framework for DNSSEC Policies and DNSSEC Practice Statements"**,
Informational, nothing to do with QNAME case — and the 0x20 mechanism has no
published specification anywhere (searched exact-phrase, semantic, and by
subject: the corpus's only trace is the expired `draft-vixie-dnsext-dns0x20`
as an informative reference inside RFC 8555). The row is closed unspecifiable
rather than implemented from memory; this track cites sections, and there is no
section to cite. The rest of the list checked out — 9824 compact denial, 10001
dual-family (§4.2 is real and recent, BCP 91), 9471 glue, 9364 umbrella — and
the HANDOFF's own "8145 §5 (padding)" was a third wrong pointer: 8145 §5 is
edns-key-tag signaling, padding policy is **RFC 8467**, which roadmap row 95
already cited correctly with its trigger condition ("the day the P4 transports
exist") now fired. The second wrong document lived in code, not prose, and is
told below where the bit itself is told.

9824 itself reads small and is a validator rewrite in disguise, because its
central move is against the implication every §5.3.2 validator trusts: an
NSEC/NSEC3 whose owner matches QNAME proves the name *exists*. Compact denial
signs exactly that shape for names that do not exist and adds NXNAME (128) to
the bitmap to say so (§2, §7.1/§7.2 amending 4034/4035 to let the pseudo-type
bit ride). The validator change is therefore deliberately narrow: the NOERROR
branch's mechanics are untouched — the matching record still proves QTYPE
absent, which is *true* even when the shape is a half-lie about existence —
and the increment only reads the bit beside the proof (`via_compact` on the
verdict, the `via_opt_out` pattern a second time), plus one NAME_ERROR branch
for §5.1's CO-restored RCODE 3. The refusals were the design work:

* NXDOMAIN + CO + a matching record **without** the bit → Incomplete, not
  Bogus, not believed: the signed body contradicts the header, and 9824 says
  nothing that licenses calling that forgery — the zone may be mid-deployment
  and sign the shape it always signed beside an RCODE it should not have
  moved. Re-ask.
* NXNAME beside a real type in one bitmap → on the NAME_ERROR branch, Bogus
  (§3.1¶2's "MUST only" read as the record contradicting itself); on the
  NOERROR branch, merely no signal — the NODATA proof stands on QTYPE's
  absence and the rest is pseudo-type noise RFC 4034 §4.1.2's ignore-rule was
  written for. Asymmetric on purpose: RCODE 3 *needs* the bit to mean
  anything; NOERROR never needed it at all.
* CO beside a conventional covering proof → inert. §5.1 adds a shape the
  server MAY send; it demotes nothing §5.3.1 already accepts.

§6¶3's ban ("[8020/8198 synthesis] cannot be realized from responses that use
Compact Denial of Existence") turned out to be mostly *structural* — the
successor forms are empty spans by construction, `\0.owner` sorts immediately
after `owner` and hash+1 immediately after hash, and the covering predicates
already refuse an empty span for every neighbour — tested that way rather than
asserted from prose. Two guards were still needed where the structure does not
reach: the walk caches a compact NXDOMAIN (restored by the zone over CO) as a
**Nodata-shaped entry** — the delivered packet keeps the zone's RCODE 3,
honest and AD-set on the verdict, but a `Nxdomain` cache entry is the shape
that cuts descendants, and 8020 synthesis from compact evidence is the exact
thing §6¶3 names; and `synthesize_denial` discards whole bundles carrying the
bit, because a cached matching record is otherwise NODATA-synthesis fuel for
every other type at a name declared gone. (The bundle-wide discard rather than
record-wide: one lie inside a proof bundle means the bundle describes no world
— differential-tested, one bitmap bit changes the synthesis to `None`.)

**The CO bit nearly landed on the wrong bit number, and its landing site was
already squatted.** §5.1's drawing shows CO beside DO; §9's IANA table says
"Bit 1". Fetched live (`dns-parameters.xml`, 2026-10-16): the EDNS Header Flags
registry numbers from the top — its "Bit 0" *is* DO, the 6891 drawing's bit 15
— so §9 and §5.1 agree and CO is 0x4000... which is exactly where this
codebase had, since the earliest EDNS rounds, a constant `EDNS_CD_BIT`
documented as "Checking Disabled — OPT FLAGS bit 14 (RFC 6891 §6.1.3, RFC 6955
§4)". Both citations are fiction: 6891 §6.1.3 assigns nothing there, and
**RFC 6955 is Diffie-Hellman Proof-of-Possession**. No EDNS registry ever
listed CD (6840 §5.5 is key-tag arithmetic; the CD that DNSSEC speaks of is
the *header's* bit 4 — untouched here, correctly cited, correctly plumbed
through §3.2.2's copy rules). The property had exactly one consumer, the CLI's
EDNS-flags print — which against any modern CO-speaking server would have
printed "cd" for a flag that has never existed. Retired: `EDNS_CO_BIT` and
`compact_answers_ok` now own the bit, the CLI prints `co`, and the removal is
documented at the constant, in the CHANGELOG, and in roadmap row 194 as the
fourth audit round's second new class of wrong (a wire constant justified by a
document from another protocol entirely). The same fetch refreshed the EDE
table (25–31 all registered since RFC 8914; 30 is 9824's, verbatim names
per the table's own policy).

§3.5's prohibition — a resolver MUST NOT forward or attempt an NXNAME query; a
server MUST FORMERR — is enforced at all four doors this package owns (CLI
parse, walk entry, stub forward, served question with EDE 30), with the enum
registered in `DnsQType` *precisely so the refusal can name the number*; the
TYPE-3597 spelling bounces the same way. The walk honors a compact signal it
never asked for — what vouches for the bit is the signature, not the request —
while `--compact-answers` remains the opt-in to negotiate §5.1's restoration,
whose downstream-querier half (§5¶2, §5.1¶5) is left unimplemented by scope:
namespy serves no downstream clients, and inventing a RCODE-rewriting egress
for a library would put this resolver's word where §5.1¶3 puts the zone's.

A find from the pre-work, tested but not touched: `validate_denial`'s NOERROR
branch has no 5155 §8.7 fallback for **NSEC3** wildcard-NODATA responses —
`_nsec3_no_data` reaches its "the covering record asserts rather than opts
out" contradiction for a perfectly signed §8.7 answer, verdict BOGUS, walk
SERVFAILs. Proven with a live fixture (apex + `*.zone.test.` chain, query
`deep.zone.test. AAAA` → bogus "denies the very existence the No Data response
claims"). `aggressive.py` knows the shape (`nsec3_proves_wildcard_no_data`,
its §5.2 fallback), which is why the whole suite passes — the wire path alone
is blind. Pre-existing, orthogonal to 9824 (compact answers route around it —
their proofs always match), and it deserves its own increment with 5155 §8.7,
errata 3441/4622, and a NSEC3 wire scenario in `test_dnssec_wiring` that today
only exists in NSEC dress. Recorded in roadmap row 155 and here.

**Verified**: 1651 passed, 1 skipped (+23: registry rows, the §4¶8 digest and
its hash-plus-one successor, the empty-span proofs, the bitmap-shape matrix,
eight validator scenarios, two scripted-walk scenarios (event, RCODE, AD,
cache-entry rcode, descendant-not-cut), the synthesis differential, the four
§3.5 doors, the flag-matrix property; 3 existing assertions re-pinned from the
fictional OPT-CD to CO, 1 EDE-table test re-pinned from code 25 to 32).
`ruff`/`format`/`mypy` clean, coverage 91.38%. Roadmap: the 9824 row ⬜→✅
(wording corrected against the document it cites), the 0x20 row closed
unspecifiable, row 194's audit round recorded, row 155 carries the §8.7/NSEC3
finding.

**Next, in order**: (1) **the §8.7-over-NSEC3 wire gap above** — it turns a
correct signed answer into SERVFAIL and predates this increment; smallest
correctness win on the board; (2) RFC 10001 §4.2 dual-family upstream
selection (roadmap row 58 🟡, citation verified); (3) RFC 8467 padding for the
encrypted legs (row 95's condition met — the codec `edns.padding_option`
exists, the policy does not); (4) RFC 9471 §3 server-side glue completeness
(row 181 ⬜, small); (5) 8509/9535 anchor maintenance (row 157 🟡); (6) DoQ
(9250) deferred as ever on the `aioquic`-sized conversation; (7) the
authority-leg DoH answer, same small remainder as before.

### Follow-up: the SERVFAIL that was — RFC 5155 §8.7 over NSEC3 (increment I)

The defect increment H proved but did not touch, now closed. The research was
one paragraph long once the paragraph was read instead of remembered: §8.7,
"Validating Wildcard No Data Responses" — "The validator MUST verify a closest
encloser proof for QNAME and MUST find an NSEC3 RR present in the response that
matches the wildcard name ... Furthermore, the bits corresponding to both QTYPE
and CNAME MUST NOT be set in the wildcard matching NSEC3 RR." No matching
record at QNAME has ever appeared in that text; the *asserting* next-closer
span that `_nsec3_no_data` read as a conviction is the section's own
precondition — the chain denying QNAME is exactly why the name earned No Data
through a wildcard rather than Name Error. Errata checked first: 5155's three
verified corrections are 3441 (§7.2.3/§8.5's two-bracket form — already in the
code), 3544 (base32hex terminology), and 4622 (§7.2.8's NSEC3-owner-name
paradox, a server-behavior section, nothing for the validator); §8.7 itself
carries no erratum, verified or otherwise.

The DS question settled on the same reading. §8.7 names no QTYPE exception —
"both QTYPE and CNAME", DS included — and §8.6 covers only the matching-record
shape of a DS NODATA; 4592 §4.6 calls a synthesized DS "meaningless", which is
about an answer's RDATA, not about a denial, and a name the chain denies can
hold no secure delegation to misreport: the wildcard-shaped DS answer means
*insecure*, which is also the right answer. The clincher was parity:
`nsec_proves_no_data`'s §5.4¶6 branch has taken the wildcard shape for DS
queries since the first DNSSEC commit, and `aggressive.py`'s §5.2 fallback for
both kinds — the wire path's NSEC3 refusal was the lone outlier, not a policy.

The change is one seam in `nsec.py`: `_nsec3_no_data`'s contradiction branch
became `return _nsec3_wildcard_no_data(qname, qtype, closest, usable, zone)`,
the adjudication extracted from `nsec3_proves_wildcard_no_data` so both entry
points share it and neither re-derives the encloser proof. Nothing else about
the refusals changed in kind: a response that *denies* its wildcard still
convicts (the pair of records is the shape of a Name Error — §8.7 against
§8.4, RFC 4035 §5.4¶6), a response that proves neither way is still
truncation's Incomplete, and the Opt-Out early-return still stands ahead of
the fallback, so the amended §8.5 keeps its insecure-delegation shape before
§8.7 is consulted and §9.2¶1's AD prohibition rides `via_opt_out` as before.
`validate.py` needed nothing: the NO_ERROR branch already caught both
`ProofError` subclasses, reads `via_opt_out` off whatever proof returns, and
takes `via_compact` through `getattr(proof, "matching", None)` — a
`WildcardNodataProof` has no matching record, so §8.7 answers are never
mistaken for §3.3.2's compact shape, which is right: compact wildcard No Data
carries a record matching QNAME (§3.3.2), a different proof entirely.

The tests re-pin two refusals and add the acceptances. `test_nsec_responses`:
the asserting-span test keeps Bogus but moves to the reason that owns it
("denies the existence of the wildcard" — the fixture's two-record chain covers
the wildcard's hash, so it is the Name-Error pair), gains the same verdict
through `nsec3_proves_no_ds`, and gains the acceptance pair — chain plus
`*.example.com.` with a typeless bitmap proves No Data through §8.5's own entry
point, DS included. `test_dnssec_validate`: `build_validator(nsec3=True,
with_wildcard=True)` asked for TXT under the wildcard — the fixture the old
code convicted — now SECURE, not compact, AD-worthy. `test_dnssec_wiring`:
`nsec3_wire_chain()` builds the chain by the tree's own hash rules (zero
iterations, empty salt, base32hex labels, wrap-around) and the scripted walk
from root to NODATA comes back `secure`, `Nodata` in the events, no
`CompactDenial`, no `AggressiveDenial`, RCODE NO_ERROR with AD set, cache entry
stamped validated. Two referral helpers gained a `qtype` parameter on the way
and lost it again when the FIFO driver proved it dead code — the file answers
question-A referrals on TXT walks already, and an unused parameter is a
promise nothing tests keep.

**Verified**: 1655 passed, 1 skipped (+4 net: two refusals re-pinned, three
shape tests, one validator scenario, one scripted walk). `ruff`/`format`/`mypy`
clean. Roadmap row 155's cross-reference note rewritten to the past tense;
README's defect bullet retired.

**Next, in order**: (1) RFC 10001 §4.2 dual-family upstream selection (row 58
🟡, citation verified); (2) RFC 8467 padding for the encrypted legs (row 95's
condition met — the codec `edns.padding_option` exists, the policy does not);
(3) RFC 9471 §3 server-side glue completeness (row 181 ⬜, small); (4)
8509/9535 anchor maintenance (row 157 🟡); (5) DoQ (9250) deferred as ever on
the `aioquic`-sized conversation; (6) the authority-leg DoH answer, same small
remainder as before.

### Follow-up: both families in play, no answer fragmented — RFC 10001 §4.2 (increment J)

BCP 91 is four months old at this writing, and the first thing the increment
did was read it: §3 is a taxonomy (misconfigurations, network conditions,
deliberate partitioning), §4.1 belongs to zone operators, §4.2 is the
recursive resolver's paragraph, §4.3 the stub's, and §5's only new sentence
is a MUST about forwarding *configurations*. Two of §4.2's paragraphs turn
out to describe this codebase.

¶1 -- "every recursive DNS resolver SHOULD be dual-stack" -- was half true
already: the transport raised a v6 endpoint beside the IPv4 one, with its own
pending queue, and the send path's comment says the caller "falls back to the
v4 ones" when v6 glue cannot be used. What did not exist was the order:
`_send_for_entry` cycled `entry.addresses` as the glue listed them, and
RFC 10001 §3.2's named fault -- a black-holed family on an otherwise living
network -- made that an answer-partitioning latency: with v6-first glue every
nameserver paid a full timeout per v6 address before IPv4 got its turn. The
fix is `_interleave_families`: alternate the two families within one entry,
starting with whichever the glue itself leads with, so one dead family costs
one timeout. Stateless deliberately. §4.2 says keep both families *in play*;
it does not ask a resolver to rank them, and the one document that does rank
families -- RFC 6724 -- is quoted by §4.3 at *stub* resolvers. The malformed
addresses a hand-seeded belt may hold go to the tail, where the send loop has
always been the thing that skips them with a log line.

¶4 -- "when responding to recursive queries ... SHOULD follow the above
guidance on fragmentation avoidance (see §4.1) ... analogously" -- opened a
bigger hole. §4.1¶4: "IP fragmentation SHOULD be avoided", "DNS-over-TCP MUST
be available as a fallback option, instead of relying on fragmented UDP
packets". The server had the TCP half (streams, 7828 keepalive, the works)
and not the UDP half: grepping the package for `TC=True` before this
increment returned *nothing* -- a namespy server had never truncated anything
in its life, and a big DNSKEY or TXT answer went out as one 1.6-kilobyte
datagram, trusting the network to reassemble what the client had explicitly
offered not to need. The client half of the house already re-asked TC over
TCP (1123 §6.1.3.2, tested); the server half never produced the bit to
trigger it. `DnsServer._fit_datagram` closes that at the single `_reply`
choke point both the answer path and `_error` pass through: cap = this
request's advertised size (6891 §6.2.3¶2's 512 floor included, §6.2.3¶7's
no-caching honoured by reading the number off the request in hand, never
from a memo), and while the wire exceeds it, records go back -- "start at the
end of the response and work forward in the datagram" (1035 §6.2¶4) --
additional, authority, then the answer's tail, which is the order that keeps
§6.2¶4's own corollary, "the answer section is guaranteed to be unique",
while any authority data remains.

The OPT record is never a victim: §7¶6 makes header + question + OPT the
floor a truncated response MUST reach and MUST NOT fall below, so the floor
loop sacrifices the record *under* the OPT before touching it, and a legacy
client (no OPT in, §7¶2) is capped at §4.2.1's 512 and answered with no OPT
at all -- truncation is not a permission slip to go extended on a request
that never asked. RFC 8914 §3's "EDE before other data" ordering survives the
layering because `_keep_explanation_inside_advertised_size` runs inside
`_apply_edns`, ahead of `_fit_datagram`'s record cuts: by the time records
fall, the explanation is already gone if it would not fit -- a test pins
exactly that sequence (3 fat records + EDE: explanation first, third record
second, TC set, OPT kept). Streams are never sized: §6.2.3¶1's number is a
*UDP payload* limit, and the stream is the fallback the TC bit promises, so
`_fit_datagram` runs only when `channel is None`. The MQTYPE combiner's
`budget` -- already the same §6.2.3 arithmetic, written separately -- now
calls the same `_datagram_cap`, one formula for "what fits this datagram".

A citation died on the way. `resolver.py`'s truncation docstring cited
"RFC 1035 section 4.3.1" for the work-forward sentence; **RFC 1035 §4 has no
§4.3** -- its tree is 4.1 format (4.1.1-4.1.4) and 4.2 transport, full stop.
The sentence is §6.2¶4's. The neighbouring §7.4 and the `packet.py` §4.2.1
citations were checked and stand. (Same failure mode as the old 9080
incident: a citation written from a feeling about where a rule lives.)

`tests/test_dual_stack_policy.py` (11): the interleave matrix including raw
belts and junk at the tail, the one-timeout-not-two proof against a stubbed
`query`, and six wire cases -- legacy 512 with no OPT smuggled, extended
1232 with the OPT kept, the stingy 128 measured at the floor, authority
emptied before the answer opens, the §7¶6 floor reached (ANCOUNT honestly
zero), EDE-first ordering, and the stream that never truncates. The server
harness is imported from `test_server`, following the fixture-reuse precedent
of the DNSSEC wiring files. (One fixture lesson: the TXT codec enforces
1035 §3.3.14's 255-octet character-string cap, so fat records are built from
200-octet chunks -- fat and legal, not illegal.)

Declined with the document open in hand: §4.2¶2/¶3's single-stack escape
hatches (PREF64 synthesis wants RA/RDNSS discovery this library does not do;
the forwarding configuration is the operator's); §4.3's 6724 sorting is for
stubs; §5¶5's forwarding-loop MUST binds configurations, not packets;
§4.1¶4's TCP MSS suggestion is an OS knob, and the project's existing answer
to path sizing is `enable_path_mtu_discovery` on its own sockets.

**Verified**: 1666 passed, 1 skipped (+11). `ruff`/`format`/`mypy` clean,
coverage 91.39%. Roadmap row 58 🟡→✅ (both halves written up, declines
named); README's truncation sentence grew a server side; CHANGELOG carries
the increment and the §4.3.1 phantom-section correction.

**Next, in order**: (1) RFC 8467 padding for the encrypted legs (row 95's
condition met -- the codec `edns.pad_option` exists, the policy does
not; the client rule is §4.1¶2's 128-octet query block -- an earlier
draft of this very sentence cited "§7's 400-octet floor", which is a
section of bibliography and a number nobody wrote, caught the same way
the F.0 phantom was, by opening the document before quoting it --
and 7830 §6 already keeps the server silent on plaintext); (2) RFC 9471
§3 server-side glue completeness (row 181 ⬜, small); (3) 8509/9535
anchor maintenance (row 157 🟡); (4) DoQ (9250) deferred as ever on the
`aioquic`-sized conversation; (5) the authority-leg DoH answer, same
small remainder as before.

### Follow-up: the size of the thing on the wire — RFC 8467 padding policy (increment K)

The padding option has had a codec since the EDNS round and a refusal
since the server round; it now has a policy, and the policy has a
number. **RFC 8467 §4.1's Block-Length Padding** ships: queries leave
over encrypted legs padded to the next multiple of **128 octets**
(§4.1¶2), which is the strategy the document recommends and the one the
walk's own charter points at -- **RFC 9539 §4.6.8.1** tells the DoT
client to authority servers that it "SHOULD use EDNS0 padding
[RFC7830]... a reasonable suggestion can be found in [RFC8467]". Three
mechanical rules were made code rather than memory: the option is
applied **last** (§3¶1) at the egress, which is where a clone can see
every option the caller already chose; the size is computed on the DNS
message, never the TCP frame (§3¶3's Transport Protocol Independence,
whose worked example -- 59 octets over UDP, not 61 -- is now a test);
and the 4-octet option header is inside the arithmetic (§4.1¶5's
zero-length option still costs 4 octets, so a message four short of a
boundary takes no payload at all).

**The gate is the transport, not the taste.** RFC 7830 §6's MUST NOT
over unencrypted transport is why `padded_clone` is a *clone*: the
opportunistic race hands one packet to cleartext and encrypted legs at
once, and the two wires must differ. The encrypted legs are
`_query_authority`'s DoT wire on the walk and `StubResolver._stream_query`
(both `dot` and `doh` pass through it, which is why one live-TLS test
covers the placement for both); the UDP and TCP legs cannot receive the
option whatever the knobs say. **RFC 7830 §4¶1's ceiling** -- padded
messages MUST NOT exceed the Requestor's Payload Size -- is read as the
sender's own advertisement (on a query, the Requestor is us), and a
boundary beyond it refuses padding entirely rather than clipping to
size, because §4.1's promise is a multiple and half a block anonymizes
nothing.

**On by default**, with `--no-query-padding` (constructor
`query_padding=False` on both resolver classes) as the RFC 8467 §3¶2
resource-conservation exit. The reasoning: an encrypted leg is a
privacy choice already made, the SHOULDs are written to clients that
made it, and the cost is bounded -- 128-octet blocks, the sender's
advertisement as ceiling, and a server's §4¶2 duty to pad the reply
back only where its own limits allow.

**A false alarm, logged because the audit that produced it was still
worth running.** Opening this increment, the `§4.6.x` citations through
`opportunistic.py` looked phantom -- RFC 9461 has no §4.6 -- and the
ADoT draft was cast as their culprit. It is not. **RFC 9539**
(Unilateral Opportunistic Deployment of Encrypted Recursive-to-
Authoritative DNS, EXPERIMENTAL, 2024-02) *is* the published ADoT
document, its §4.6.1-§4.6.12 are the probing policy the module
implements, and its errata are *exactly* the verified 7831 and 7832 the
docstrings cite. Every such citation in `opportunistic.py` and
`resolver.py` is attributed correctly to 9539; the ones naming 9461
(_dns mapping, port defaults, discovery limits) are correctly 9461's.
Two dangles were real, and both died: "that is the RFC 8145 section 5
row" (8145 is edns-key-tag; the padding row is 8467 -- increment H's
correction that never reached this sentence) and increment J's
"§7 400-octet floor" above, corrected in place. Lesson kept: the audit
procedure (open the document, read the section) is just as load-bearing
when it clears a suspicion as when it confirms one.

**Declined with the documents open in hand**: §4.2's alternative
strategies (random block sizes and the rest -- §4.1 is the recommended
one, and two policies on one wire buy an observer variance, not
anonymity); the **468-octet response block** (§4.1¶3) -- a server's
duty toward padded queries, and `namespy.server` has only cleartext
fronts, where §6 forbids the option arriving or leaving; DoQ's padding
counterpart (RFC 9250 §5.4, deferred with the whole transport); and the
server replying to a padded query with padding of its own over plaintext
(7830 §6 again -- the existing `test_padding_asked_for_over_plain_udp_
is_not_honoured` remains the right behavior and now has neighbors).

**Verified**: 1678 passed, 1 skipped (+12, all in `test_padding_policy.py`:
the §3¶3 worked example, the §4.1¶5 zero case, last-option ordering,
the §4¶1 budget refusal, the walk's padded wire and its untouched
cleartext twin, live-TLS stub ordering, UDP's permanent silence, the
CLI flag both ways). `ruff`/`format`/`mypy` clean, coverage 91.4%.
Roadmap row 95 ▫️→✅ (the row-83 rationale grew legs honest: plaintext
UDP is no longer "every transport here"); README's "not yet *used*"
sentence rewritten; `opportunistic.py`'s not-yet-exercised list lost its
padding item and its 8145 tail.

**Next, in order**: (1) RFC 9471 §3 server-side glue completeness
(row 181 ⬜, small) -- closed the same day by increment L below; (2) 8509/9535
anchor maintenance (row 157 🟡);
(3) DoQ (9250) deferred as ever -- and it inherits this increment: its
§5.4 padding guidance rides the same `query_padding` decision whenever
the transport lands; (4) the authority-leg DoH answer, same small
remainder as before.

### Follow-up: the referral the tests never sent — RFC 9471 §3 (increment L)

Row 181 had sat ⬜ since the server rows were written, and the honest
opening move was to read the document (four tight pages, no errata) and
the code (increment J's `_fit_datagram`) before writing anything. Both
were already right: J truncates from the end of the datagram, which eats
ADDITIONAL -- the glue -- before AUTHORITY -- the NS set -- and raises TC
on any drop, which is precisely §3.1¶1's "MUST include all available
glue records... or MUST set TC=1 if constrained by message size" and
§3.3's update to RFC 1034 step 4c. What no test had ever done is *send a
referral*: every truncation test since J truncated a fat answer, and a
referral's payload lives in the two sections those tests exercised last
or not at all. So increment L is proofs, not production: four tests in
`tests/test_referral_glue.py` drive hand-built referral shapes (NS set +
A/AAAA glue per §2.1's example) through the real responder.

What the tests pin: glue whole and the header silent when it fits;
TC=1 and twelve glue records trimmed-from-the-tail while all six NS
records stand when the client advertises 512 and the zone was fatter; the
legacy no-OPT client under the same rule at 1035 §4.2.1's 512 (with
6891 §7¶2 still refusing to invent an OPT); and a 128-octet advertisement
measured as 512 (§6.2.3¶2) buying the referral untrimmed -- TC reserved
for real constraint. The first run taught one thing worth recording:
three nameservers with dual-stack glue *fits* 512 once the codec applies
§4.1.4 name compression -- the fixture is better behaved than the
truncation test assumed -- so the size cases went to six servers, which
overflow with room to spare.

Cleared rather than coded, with the reasons in the roadmap row and the
CHANGELOG: §3.1¶2's client half ("most iterative clients... retry over
TCP upon receiving a response with the TC flag set") is the walker's
long-shipped RFC 7766 behavior, already pinned in
`test_resolver_truncation.py`; §3.2's sibling-domain preference -- drop
sibling glue before in-domain glue -- is an authority's arithmetic, and
this fixture serves no zone, so it has no bailiwick to classify records
by; J's blanket TC on any drop is in fact *stricter* than §3.2's
unobligated MAY. The genuinely-authoritative reading of the row ("grow a
zone-serving mode and include all available glue at composition") is the
feature line 182's cell already declines: "it is a test fixture, not a
service". Row 181 ⬜→✅.

**Verified**: 1682 passed, 1 skipped (+4). `ruff`/`format`/`mypy` clean,
coverage 91.4%. Roadmap row 181 ⬜→✅; CHANGELOG carries the increment.

**Next, in order**: (1) 8509/9535 anchor maintenance (row 157 🟡 --
acquisition shipped, refresh-on-schedule and rollover handling did not;
the sentinel shipped as increment M below, and the list's "9535" turned out
to be JSONPath);
(2) DoQ (9250) deferred as ever, its §5.4 padding riding the
`query_padding` decision whenever the transport lands; (3) the
authority-leg DoH answer, same small remainder as before.

### Follow-up: a questionnaire for the trust store — RFC 8509's sentinel (increment M)

Row 157 opened with a citation audit of its own -- and this one found a
real phantom. The row (and every "next" list back to the earliest
handoff rounds) named **RFC 9535; RFC 9535 is JSONPath**. Nothing was ever
specified by it; the rollover-timing document the list half-remembered is
RFC 7583 (INFORMATIONAL, a timeline of DNSSEC key-rollover events), and
the normative anchor-maintenance mechanism the row actually names is RFC
8509's sentinel -- which is not a refresh scheduler at all, whatever the
handoff's prose had been assuming for a dozen rounds. Reading the document
before coding is the whole increment's method again.

What 8509 actually specifies is a questionnaire: §2's two labels,
``root-key-sentinel-is-ta-<key-tag>`` and ``...-not-ta-<key-tag>``, asked
of a validating resolver so its answers reveal the trust-anchor store it
carries -- on KSK-ceremony night, exactly the thing an operator cannot
otherwise see. §2.2¶4's table is the protocol (claim matches store:
original answer; claim contradicts it: §2.2¶5's SERVFAIL with an empty
Answer Section), §2.1 is six preconditions any one of which forbids
alteration, and §2.1¶9 is precision law: the key tag is "zero-padded to
five digits" and a near-miss label is an ordinary name. That last rule
does real work here: the actual ceremonies queried ten-digit labels
carrying a key *identifier*, which §2's 16-bit key-tag arithmetic can
never match -- this implementation follows the document as written,
processes those as ordinary queries, and says so in the parser's docstring
rather than inventing a laxer dialect nobody standardized.

`namespy/anchors.py` gained `sentinel_expectation` (label shape, exact)
and `trusted_anchor_tags` (the store, live: §2.2¶2's AddPend/Revoked
exclusion read through RFC 9718 §2.2¶7's windows, since this package
keeps no 5011 state machine -- a future `validFrom` is as untrusted as an
AddPend, a closed `validUntil` as a Revoked; root-zone-only, because
§2.2¶2 speaks of root KSKs). `DnsServer._sentinel_gate` enforces the
preconditions, each with its own exit, and reads the validation verdict
*before* RFC 6840 §5.8's courtesy AD strip -- the precondition is about
what the resolver knows, not what this client asked to see; a refusal
withdraws AD with the answer it used to describe, and outranks the MQTYPE
combination (§2.2¶5's "ignoring all other documents"), the support claim
surviving as the empty list that already serves an unanswered query.
Eighteen tests ask every cell of the table, every precondition's inertia,
both edges of the validity window, the above-range-but-legal 65536, and
the ten-digit ceremony name end to end.

Declined, reasons in the row: §3.1's forwarder half (a forwarding resolver
is supposed to fire its own synthetic sentinel at its upstream and mirror
the verdict; namespy's forwarding path mirrors the upstream's *answer*
already, and per-upstream ceremony testing is deployment scope the fixture
declines like it declined RRL); RFC 5011 auto-add (its own future row --
the sentinel is explicitly a store *test*, not a store *writer*); and a
refresh schedule, which no document in the row's own citation list asked
for: re-acquisition is one `fetch_root_anchors` call from the operator's
cron, and the sentinel is what proves the call landed. Row 157 🟡→✅.

**Verified**: 1700 passed, 1 skipped (+18). `ruff`/`format`/`mypy` clean,
coverage 91.5%. Roadmap row 157 🟡→✅ with the 9535→7583 correction;
README's "open roadmap row" sentence rewritten to describe the
questionnaire; CHANGELOG Added carries the increment.

**Next, in order**: (1) the authority-leg DoH answer -- closed by
increment N below without writing a line of transport code: it was a
refusal misfiled as a remainder; (2) DoQ (9250) deferred as ever, its
§5.4 padding riding the `query_padding` decision whenever the transport
lands; (3) RFC 5011 as its own honest row if active maintenance is ever
wanted (it would *write* the store the sentinel now lets you *read*);
(4) the standing human task: the first release tag the Status section has
been waving at for ten rounds.

### Follow-up: the remainder that was a refusal — authority-leg DoH, read whole (increment N)

The queue's oldest resident -- "the authority-leg DoH answer, same small
remainder as before" -- closed without a line of transport code, because
the sentence was never true. RFC 9539 §2.2¶8, read whole for the first
time this round, is not a gap in the document's coverage of encrypted
transports; it is a declined one: "This document does not pursue the use
of DNS over HTTPS... because a DoH client needs to know the path part of
a DoH endpoint URL. Currently, there are no mechanisms for a DNS
recursive resolver to predict the path on its own... If such mechanisms
are later defined, the protocol in this document can be updated to
accommodate them." And §2.2¶7 binds everything the state machine manages
to the two transports actually specified: "The protocol described in this
document specifies the use of DoT and DoQ."

The interesting part of the audit is that §2.2¶8's premise is arguable
now: the path mechanism the paragraph wishes for is close to what RFC
9461 §5's ``dohpath`` SvcParam provides -- a URI template published in
the same `_dns` SVCB records this walk already consults, with §5¶2
spelling out the origin and the expansion. But 9539 cites RFC 8484 while
never citing 9461 at all (both reference lists checked), §2.2¶7 keeps
the machine DoT/DoQ-only, and the update clause is written as a future
event: "can be updated to accommodate them." Implementing DoH-to-
authority here would mean running a third transport through a Table 2
whose formulas were never drafted for it, on a reading the governing
document has not made. The project's own rule -- the one that declined
the serving side of compact answers in the H round ("online signing is
out of this repo's scope") and every serving-roadmap row RRL answers with
("it is a test fixture, not a service") -- is that a nice-sounding
extension is not a spec, so the increment is the opposite
of a build: it retires the to-do.

What made this worth a round anyway: the *code was already right*. The
discovery layer skips an alpn without `dot` with a `_SkippedError`
(citation attached), and `test_discovery_doh_only_record_describes_no_
dot_endpoint` has pinned the HTTP-only record's fate since the P4 round
-- what was wrong was three sentences of prose calling a declined avenue
a remainder, and the queue dutifully carrying them for eight rounds. The
docstring bullet now cites §2.2¶8 as the standing refusal it is, records
the dohpath tension honestly (9461 §5 arguably answers §2.2¶8's wish; the
amendment still has not happened), and notes that the paragraph's own
resource concern -- a path-guessing client "incurring an excessive use of
resources" -- is a second reason the skip is the right default even
tonight. Roadmap row 56's deferral list gained DoH with the citations;
the CHANGELOG's Changed section carries the retirement.

If a future 9539 bis does ratify dohpath-based DoH for the authority
leg, the seam is ready and small: `learn_dot_endpoint` already parses
the parameter (the SVCB codec has carried `dohpath` since the 9460
round), the DoH machinery exists in `namespy/doh.py`, and §4.6.8.1's
padding knob already reaches any encrypted egress. What would have to be
written is the state machine's blessing -- and that is the amendment's
job, not this package's.

**Verified**: 1700 passed, 1 skipped (+0 -- behavior unchanged, prose
corrected). `ruff`/`format`/`mypy` clean, coverage unchanged at 91.5%.

**Next, in order**: (1) RFC 8145's actual subject -- edns-key-tag and the
`_ta-` DNSKEY-query signalling (row 158 🟡, the last open item on the
EDNS/DNSSEC maintenance list that is *not* waiting on a dependency or a
human) -- shipped as increment O below; (2) DoQ as ever; (3) RFC 5011 as
its own row if active store maintenance is ever wanted; (4) the standing
human task: the first release tag.

### Follow-up: the question that says who validates — RFC 8145 §5 (increment O)

Row 158's own note said the rest of 8145 "is its actual subject,
edns-key-tag and `_ta-` key-tag signalling on DNSKEY queries,
unimplemented" -- and the audit found the sentence half right. §4 had
shipped long ago, down to §4.2.2.1¶2's two lists riding as separate
instances of the option and §4.2¶6's two-source gate (anchors and DS, the
`key_tags_for` docstring still citing the rollover-telemetry laundering
argument); `test_edns_keytag.py` has held all of it. What never shipped
was §5: the *query*, the NULL/IN question whose first label spells the
trust-anchor key tags in four-digit hex.

`anchors.key_tag_query_name` is the whole format (§5.1¶2-¶5): `_ta-`, the
tags zero-padded to four lowercase hex digits, hyphen-joined, sorted
smallest to largest, over the zone. The document supplies its own test
vectors and they are the tests: 17476 is `_ta-4444.` (¶3), 999 is `03e7`
(¶4), and the three-anchor example comes out
`_ta-0635-7aae-aa1b.example.com` when fed unsorted (¶5). Nothing to
encode for an empty list and nothing to encode past 65535 -- the tag is
Appendix B's 16-bit arithmetic, and a label truncating a number the
operator reads back as telemetry (§7¶1) is the one formatting "generosity"
that turns a bug into misinformation.

The trigger is `RecursiveResolver._maybe_key_tag_signal`, hooked at the
driver's SendQuery completion -- the one point every DNSKEY question
passes, the chain helper and the user's own query alike, which is what
§5.2¶1's "whenever it also originates a DNSKEY query" describes. Three
doors, each §5.2's own: ¶4's MUST NOT for non-validating resolvers reads
as *no anchors, no signal* (the same honest inertness as the sentinel and
VALIDATED cuts); ¶3's SHOULD NOT keeps DS-learned zones off the query
path -- their tags stay on the §4 option, which admits them, and get no
question of their own, which does not; and ¶2's "the trust anchor that
will be used to validate" scopes the match to configured anchors,
active() at that -- a window that closed validates with nothing.

The answer belongs to the *operator* (§5.3¶1's MAY-log is the entire
point -- this is how a zone learns whether anyone still trusts the old
KSK before withdrawing it), so the send rides as a background `resolve`:
no RTT added to work that has a client waiting, exceptions consumed and
dropped the way the probe-learning tasks do. The full path was a
decision, not a shortcut's opposite: §5.2¶5 asks a caching resolver to
cache and reuse the response "just as it would any other response", and
the one word *any* rules out every door that skips the cache -- so the
glance at `cache.get` before firing is ¶5 read as an instruction not to
re-ask, and the in-flight set both stops one descent counting its
telemetry twice and bounds the recursion the full path invites (the
background walk validating its answer re-fetches the zone's DNSKEY, whose
SendQuery lands back on the same method and finds the signal already
running).

The server half was already right, and stayed right: §5.3¶2 demands only
an "appropriate response... determined by whether the data is in the zone
file" -- the fixture resolves a NULL query as any other, its NXNAME
FORMERR gate (9824 §3.5) demonstrated to be that type's own door and not
a Meta-TYPE amnesty. §4.3¶2's MUST NOT -- no edns-key-tag in any
response -- got the first explicit test the rule has had.

Declined with the document open: §4.2.2.1¶3's MAY of *combining* the two
lists into one option (separate instances is ¶2's transmitted shape and
the one a collector can disaggregate); §5.3¶3's zone-side `_ta-` NULL
records (a zone-content suggestion for operators, and this fixture serves
no zone); and the §5.3.1 interaction tuning (aggressive-cache suppression
of repeat signals is already the cache glance's behavior in the client's
half of that sentence). 13 tests; row 158 🟡→✅.

**Verified**: 1713 passed, 1 skipped (+13). `ruff`/`format`/`mypy` clean,
coverage 91.5%. Roadmap row 158 🟡→✅; CHANGELOG Added carries the
increment.

**Next, in order**: (1) DoQ (9250) -- the last deferred transport, still
gated on the `aioquic` decision, its §5.4 padding and now its §5
telemetry both already hooked; (2) RFC 5011 as its own honest row if
active anchor maintenance is ever wanted; (3) the standing human task:
the first release tag. The maintenance queue that the phantom-9535 list
carried for a dozen rounds is, at last, empty of everything that was
real.

### Follow-up: the documents that arrived after the algorithm table — RFC 9905/9906 (increment P)

The row-155 audit turned up two November-2025 INTERNET STANDARDS that sit *beside*
RFC 9904's table rather than inside it — §4¶2 of RFC 9905 says outright the
Implement/Use columns are "not changing" — so the capability table stayed as it was
and an accept-side policy layer went next to it: four sets in `crypto.py`, one per
document per record kind, because 9905 deprecates by the DS's **Algorithm** octet and
9906 by its **Digest Type** (3, the GOST hash as RFC 5933 §4.1.2 denotes it), and confusing the
two fields is the one way to get both documents wrong at once. The DS exclusion is
unconditional in both documents and lands before any digest arithmetic runs; when
deprecated records were all the trust point, the link answers the new
`ChainOutcome.INSECURE` — the documents' own word, and a genuine fourth state: not
contradicted (BOGUS), not unexaminable (INDETERMINATE), **void**. §2¶2's signature
sentence is the asymmetry worth keeping in mind: *operators* MUST start from
unsupported, *implementations* MUST keep the arithmetic, which is exactly a default
plus a named opt-in (`allow_deprecated_sha1` → `--allow-sha1-dnssec`), and RFC 9906 —
no continue-to-support sentence — got no opt-in. The mapping upward honours the word
the documents chose: DEPRECATED answers route to *insecure* (served, unsigned), never
bogus and never SERVFAIL, while merely-UNSUPPORTED keeps deferring — precedence is
bogus > indeterminate > insecure, because a check that awaits a backend might yet pass
where a forbidden one never will. Two vocabularies changed shape in the process, both
on review: the boolean marker first sketched for "deprecated" became a fourth
`SignatureOutcome` member (a conclusion belongs in the outcome enum, not beside it),
and `_verify`/`_verify_proofs` stopped returning string dialects of `SecurityStatus`
and return the enum itself — every `kind == "bogus"` in the module is gone. One test
fixture error surfaced the labels discipline on the way: an apex self-signature over
`example.net.` carries Labels=2, and the reconstruction check (correctly) refuses 3
before the arithmetic tier, turning a would-be INDETERMINATE into BOGUS. Full suite
1723 passed, 1 skipped. The same audit closed roadmap row 130 as a phantom-citation
non-goal (RFC 6841 is the DNSSEC Policy/Practice framework; 0x20 case entropy was
never standardized — `draft-vixie-dnsext-dns0x20` expired in 2013 and no published
RFC mentions the technique). What remains on the horizon is unchanged: the release
tag (human), DoQ (dependency decision), RFC 5011 (its own row when wanted).


### Follow-up: anchors that replace themselves — RFC 5011 (increment Q)

The queue said "its own row when wanted"; the row is written and the module
shipped with it. RFC 5011 is a small document with one load-bearing sentence —
§4¶2's "The table is a normative part of this specification" — so `maintenance.py`
is a faithful transcription of the §4¶3 table and nothing else: six events, six
states, an injected clock, no sockets. Three transcription decisions are the ones
to review. (1) **Identity is (algorithm, key material), never the key tag** —
§2.1¶4's aside that a revoked key "has a different fingerprint" is the whole
mechanism's trap: flags are inside the digest that produces the tag, so a
tag-indexed machine watches A revoke, forgets A, and re-adds A from its own
revocation ceremony. (2) **RevBit runs as its own first pass** over the received
RRSet — §3¶1's "permanently invalid for all purposes" outranks every other event,
including §2.2¶2's validator-honesty test, which must therefore see revocations
taken in the *same* observation (§6.4's compromise scenario is exactly this race,
and a test drives it with the pending key listed first). (3) **Missing keys stay
trusted.** §4.2¶4's "remains a valid trust-point key" reads like a leniency and is
actually §2.1¶1's threat model made operational: if absence demoted an anchor, a
compromised key B could retire honest key A by simply not listing it. Removal
from the trust set happens only by self-signed REVOKE, immediately and permanently
(§2.1¶2), with the hold-down machinery (§2.2¶2's three reset clauses, §2.4.1¶1's
greater-of) gating only the *addition* direction — and the greater-of is what
makes §2.4.1¶1's "at least two validated DNSKEY RRSets" a theorem rather than a
hope, since AddTime can only fire inside an observation, and the first observation
started the clock. §5 is exposed honestly: ¶1's deletion quantifies over anchors,
not tracked rows (a pending key is no unrevoked anchor, so an all-revoked point
with a candidate in flight reads deleted, which is exactly true at that instant),
and ¶2's 180 days — "a local configuration decision" by its own words — ships as
a predicate, not an action. §2.3's cadence formulas ship too (both MAX/MIN pairs,
floors and ceilings tested) because the operator's cron has to compute them
somewhere even though this module will not run itself. The managed-key document
round-trips state and timers (format ours — the document specifies none, and JSON
keeps the zero-dependency promise); §2.2¶4's until-explicitly-revoked promise does
not survive a restart without it. 19 tests, full suite 1742 passed, 1 skipped.
Not done, deliberately: no scheduler (the 8509 row's cron story stands), and no
resolver fetch wiring — observe()'s contract is that the caller is the validation
walk, and a deployment decides where its anchor fetches come from.


## Previous round: MQTYPE (RFC 10029)

Shipped: the wire form of both options in both directions, the server's half of using them
(§3.4's combination), and now the client's half too — `RecursiveResolver.resolve_bundle`
asks, `namespy.bundle` reads, and `--mqtype` puts both on the command line, so an
A + AAAA + HTTPS lookup is one descent instead of three.
`namespy/mqtype.py` composes MQTYPE-Query (20) and MQTYPE-Response (21), parses either,
and holds the §3.3 rules on the way out as well as the way in — §3.2 makes a client
responsible for "packets that conform to the server request parsing rules described in
Section 3.3", so one `_offence()` serves both ends and they cannot drift apart about what
is valid. Two codes rather than one code plus a flag, because the directions are not
symmetric: §3.3 refuses an inbound MQTYPE-Response outright, while §3.5 makes the
*absence* of one the way a server says it does not support the extension — so an inbound
response option is a FORMERR and an empty outbound one is a legal "supported, but there
was nothing to combine" (Appendix A.3's DS-plus-NS figure is exactly that case). Things
worth knowing before editing:

- `mqtype_supported()` never raises and `mqtype_answered_qtypes()` does, on purpose. A
  second option, a repeated QTx, or a QTx equal to the primary QTYPE means "treat the
  answer as invalid (equivalent to FORMERR)" (§3.5), which is a *different* instruction
  from "unsupported"; one boolean covering both would keep using an answer the client was
  told to discard.
- Whether a number may be a QTx is RFC 6895 §3.1's partition, not a range check, which is
  why `enums.rrtype_class()` is new: `OPT` (41) is a Meta-RR numbered *inside* the data
  band, 128–255 is a gap the allocation policy never gave to data, and an unassigned 300
  is a perfectly good QTx (refusing it would repeat RFC 3597 §3's mistake). `NXTYPE` (40)
  and `OPT` (41) are the trap a `<= 55` test walks straight into.
- `qtypes_still_needed()` is a work list, not a negative answer. A missing QTx has four
  innocent reasons — §3.5's own list — and none of them is NXDOMAIN or NODATA, so no
  caller may cache a negative from it.
- The combine loop runs inside the egress slot the primary lookup took, so what RFC 10029
  §4 says about amplification stays true of this server: one client, one outstanding
  upstream query at a time, whatever it asked for. `_standalone_query` sets
  `edns_override=True` because the copy of the requestor's OPT is what carries the copy of
  its payload size — and it drops the MQTYPE-Query on the way, because a query that echoes
  a QTx at the responder is a second question, not the same one asked twice.
- Three stops, three meanings, one list. The size rule withdraws a QTx it cannot deliver
  whole — measured by `_prospective_size`, which pays for the option's own octets before
  naming a type — and the records go back the way they came; `max_qtypes` shortens the
  work list because an operator decided a question may not cost that many lookups; a `TC`
  primary forbids the extra queries outright, since the complete answer can only arrive
  over TCP, where the loop runs again and the option travels with the answer that reaches
  the requestor. All three return `answered` as far as it got. RFC 8914 §3's
  drop-EDE-first rule rebuilds an oversized reply *around* the MQTYPE-Response: the
  explanation is the one option a size rule is allowed to eat.
- `_record_key` is RFC 2181 §5's identity plus the section, deliberately. TTL is not part
  of what makes a record the same record, and a NODATA answer legitimately carries one SOA
  twice — once in the Answer section denying the type, once in the Authority section
  proving the name exists. Keying without the section quietly "fixes" that.
- `namespy/bundle.py` reads and never sends; the resolver walks and never interprets. That
  split is what keeps a cached lie out of the design: the reader decides what an answer says
  about each requested QTYPE (`BundleState`), and the resolver decides what may be stored,
  which is only what the answer vouched for. An unlisted type is `NEEDED`, §3.5's four
  innocent reasons being the reason it is a work list rather than a verdict, and
  `resolve_bundle` re-asks it (§3.5: "The client MUST subsequently initiate separate
  standalone queries") unless the caller passes `ask_separately=False`.
- `supported` and `void` stay two fields, and the void is handled in `resolve_steps` *before*
  classification reaches the cache. A duplicated QTx or a second MQTYPE-Response is
  "equivalent to FORMERR" (§3.5) and discards the primary answer with it, so a client that
  cached the primary on its way to rejecting the bundle would be storing an answer it has just
  been told to throw away; `test_an_invalid_answer_is_discarded_before_it_reaches_the_cache`
  is the pin. Unsupported is the opposite case — the answer is good and is used as-is.
- The option is threaded through the walk rather than attached to one query, and the lookups
  that merely support the walk are kept out of it. A QNAME minimisation probe sets
  `bundle = ()` explicitly: it asks about a shorter name than the extras were requested for,
  so §3.4's per-combination flags would be the probe's and a server would be invited to
  combine RRsets for a name nobody asked about (`test_a_minimisation_probe_never_carries_it`).
  Glue sub-resolution needs no such guard — the list travels only in the one walk that was
  handed it, so every other walk starts empty by construction.
- `BundledType.separate` says whether a type's answer arrived in the combined reply or in a
  query of its own, and only `reasked()` ever sets it. It looks redundant next to `response`,
  which a re-ask fills in at the same moment, and it is not: `--mqtype` against today's
  authoritative servers takes the re-ask path *every time*, and the first version of the CLI
  report printed "combined: 2 record(s) in the answer above" over an Answer section holding
  two A records. Where an answer came from is a fact about the exchange, not something a
  renderer should infer from a record being present — `test_an_answer_bought_separately_is_not_reported_as_combined`
  is the pin, and `_format_short` filters on the same field rather than on record identity.
- The UDP fallback is three tiers in RFC 6891 §6.2.2's own order: FORMERR whose reply carries
  an OPT loses the MQTYPE-Query and nothing else; FORMERR with no OPT loses EDNS entirely;
  both re-run the walk. A server that has never seen option 20 therefore costs one more
  exchange, never an answer — which is the same promise `--nsid` makes.

§4's four-QTx guideline is exported as `MQTYPE_RECOMMENDED_QTX_LIMIT`, which is the default
of `DnsServer(max_qtypes=...)` and the default of the CLI's `--max-qtypes` — one constant, so
the two cannot drift
about what an undecided operator gets. An operator may raise it, or pass `None` to leave
the list bounded only by what an EDNS option can hold at all: §3.1 gives OPTION-LENGTH no
count field of its own, so it is RFC 6891's 16-bit option length (which `EdnsOption`
enforces) and the advertised UDP payload that cap the list, not any number RFC 10029
states. Zero is worth naming because it is not a smaller version of the same
refusal: it answers the option and combines nothing, which is a server declining this
much work, while silence is a server that cannot do the extension at all. Passing the
flag is what keeps the CLI honest here — an absent `--max-qtypes` wired through as
`None` would have quietly meant *unlimited*, which is the opposite of the conservative
default §4 asks for.

The asking side is deliberately not held to that number. §4's guideline is advice about how
much work to take on, `query_option_for` enforces only what §3.3 makes mandatory, and a server
that thinks a list is too long already has a legal way to say so: leave the tail out (§3.5's
"the server was unwilling to process the request (for example, because a limit was exceeded)"),
which the client reads as work left over and re-asks. So five `--mqtype` flags may return four
combined and one fetched separately; what they can never do is turn that omission into a
negative answer about the name.

`tests/test_mqtype.py` (44 tests, Appendix A's three figures as the oracle), sixteen
tests in `tests/test_server.py` — the refusals, the combination rules down to the bytes of
the option on the wire, the operator's limit at both ends of its range, and one test that
holds the EDE and MQTYPE size rules in the same packet — and 22 in `tests/test_enums.py`
pinning every boundary of the §3.1 table. `mqtype.py` is at 100% coverage. On the asking
side, `tests/test_bundle.py` (28) covers the reader — §3.5's outcomes, every invalid shape,
the ownership rules a harvest is held to — and `tests/test_resolver_mqtype.py` (28) covers
what a walk does with it: the option on the real question and never on a minimisation probe,
the three fallbacks, the cache rules including the one that must never fire, and demotion
when a server on the path contradicts itself. Twelve more in `tests/test_cli.py` hold the
flag and its rendering. `bundle.py` is at 100% coverage too.

### Follow-up: the two halves, on one wire

The asking side shipped with every test on one side of the exchange writing the bytes the
other side read — which proves nothing about whether the two agree. `tests/test_mqtype_interop.py`
now runs a real `RecursiveResolver` against a real `DnsServer`:

- The splice is at the **transport**, not at `query()`. `_Loopback` replaces the client's
  socket with a queue; a pump task hands the bytes to `DnsServer.datagram_received` and feeds
  the reply back through `Resolver.datagram_received` under the *peer address the query went
  to*. That last part is not a detail: `_pending_key` implements RFC 5452 §9.1 (address + ID +
  question), so the client's matching discipline is still under test with the wire simulated.
  Splicing at `query()` instead would have had the test build the packet itself, which means
  re-implementing the encoder it is supposed to be proving.
- The server's upstream is stubbed at `resolver.resolve` (the same seam `test_server.py`
  uses) and the client's whole world is one seeded root, so a bundled lookup is one datagram
  and a declined one is three — which is what the tests count.
- **It caught a real defect immediately.** Ten fixtures used `b"\x00\x00\x00\x01"` as HTTPS
  RDATA: priority 0, target `.`, one stray octet — malformed under RFC 9460 §2.2, which is why
  the client was discarding an otherwise perfect reply. They survived because those records
  never went through the wire codec. The lesson is general: a hand-built `DnsRecord` is not a
  parsed one, and any fixture that claims to hold RDATA should be able to survive
  `bytes(record)` and come back.

`--trace` gained the visibility the CLI report already had. `SendQuery.extra_qtypes` was
already on the effect, and the re-ask traces already existed — they were just thrown away when
`resolve_bundle` restored the bundling descent, so the file showed one descent for a run that
had sent three. Bundling hops now render as `(mqtype +2)` and each re-ask is a child trace
(`_walk(..., trace=)`, the same mechanism glue sub-resolution uses). Note the contract the test
pins: **the child's title is set by `_walk`, not by the caller**, because qualification happens
inside the walk — a child titled from the caller's relative name would disagree with the
query on the wire.

Also fixed here: `docs/rfc-map.md` still claimed EDNS(0) was decoded but never sent, and its
code-mapping table had no row for any of the last four features. When a feature lands, its row
belongs in that table in the same commit — that document is where a contributor looks to find
out whether a rule is deliberately absent.

## Earlier round: Extended DNS Errors (RFC 8914)

Shipped: the `ERROR` option (code 15) is written *and* read. `ExtendedDNSError` in
`namespy/edns.py` holds the INFO-CODE plus the raw EXTRA-TEXT octets and infers nothing
from either — §3 forbids reading a meaning into a code, §6 forbids the option changing
anything. `.option` turns one into a TLV; `extended_errors_of` returns a response's whole
list in wire order and raises nothing, because a malformed option is something a
*receiver* skips (`extended_error_option_valid`) while the server answers one with FORMERR
under RFC 6891 §7 — same octets, opposite directions, and that asymmetry is the point.
`namespy/server.py` sends exactly two codes: 22 (`_own_failure_errors`) for a walk that
ran out of authoritative servers, 21 for a non-QUERY opcode, each with EXTRA-TEXT naming
this software; `_apply_edns` drops explanations before anything the client asked for when
the reply would overflow its advertised size (§3's order), decorates nothing for
BADVERS/FORMERR, and says nothing at all to a requestor that sent no OPT. On the way in,
`resolver._extended_error_note` folds up to three codes into the reason a `FailureCache`
entry remembers and `_note_upstream_errors` logs at DEBUG; `__main__._response_errors`
prints `; EDE: 22 (No Reachable Authority): text` under any rcode, control octets escaped,
because §6's MITM sentence describes the field a terminal is about to be handed.
Patterns worth reusing: `test_cli.py`'s `_explained(*errors)` builds a NOERROR answer that
carries options — the only sane way to pin §3's "accept them in all messages" without a
network — and `test_failure_cache_resolver.py`'s `_drive` return value pins what a
received code *changed* (the remembered reason) beside what it did not (nothing else).
Absent on purpose: no propagation of an upstream code to this resolver's own client (§3
permits either answer, and the failure path returns `None` rather than a message to
decorate), and no invented name for a code the registry does not carry — it prints as its
number. Worth knowing: every §2/§3/§6 quotation in the EDE code was re-checked against the
RFC body this round, and three that had crept in as paraphrases were replaced — the rule 8
failure mode is alive, so re-check a quote rather than trusting the section number beside
it. Shipped since that was written: SVCB and HTTPS (9460) — `namespy/svcb.py` with the
key registry, `SvcParams`, `SvcbCandidate` and `select_records`, plus `RData_SVCB` and
`RData_HTTPS` in `rdata.py`, with Appendix D of the RFC as the test oracle. Two things
worth knowing before touching either file. First, a malformed `HTTPS` RDATA now fails the
whole message parse, as a malformed `A` or `SOA` always has: the codec is registered, so
"opaque fallback" applies only to types with no codec (RFC 3597 §3), and refusing to guess
where the next record starts is RFC 9267 §5 rather than a local preference. Second,
`namespy/svcb.py` measured 70% under `pytest --cov` while the note in `pyproject.toml`
expects 89% or better, because much of its presentation layer was exercised only by
doctests and CI runs `pytest -q --cov` without `--doctest-modules`. Writing those examples
into `tests/` is what found the two bugs fixed in the same commit: `_PARSABLE_KEYS` was a
set of key *names* while `SvcParams.from_wire` and `to_wire` compare key *numbers*, so no
registered key ever matched and every one was treated as uninterpretable — a one-octet
`port` therefore decoded as a well-formed record that merely has no `port`, which changes
how a client connects instead of losing the record, because §2.2's third malformed
condition was never reached — and `SvcParams._unknown` came from how an object was built
rather than from what it stores, so a hand-built `SvcParams` could not say which of its
keys have no value definition. `SvcParams._unknown` is now derived from the stored keys,
which is also what keeps `ech` (registered at 5, no value definition) opaque in both
directions: `test_ech_is_conveyed_but_stays_opaque`'s `unknown_keys == (5,)` on a
hand-built `SvcParams` is the pin. What is
still doctest-only is `zone_file_warnings` (svcb.py:1325–1368), which leaves the module at
88% — chase that by moving those examples into `tests/`, not by writing weaker tests.
What remains in `docs/roadmap.md`, in order: wildcard synthesis (4592 §2.2) is now at the
head of the queue -- MQTYPE's asking side, which used to lead it, shipped in the round above.

Housekeeping that turned out to be a real fix: the coverage floor had never been *read*
by CI. `[tool.coverage.report] fail_under` is a pytest-cov input, and pytest-cov measures
only when `--cov` is passed — the Test step ran plain `pytest -q`, so it exited 0 whatever
the tests covered, while README, CONTRIBUTING and the pyproject comment all said the floor
was "enforced by pyproject". The step now runs `python -m pytest -q --cov`, the three docs
say so, and the comment's stale module figures (measured before this round's tests
landed) are
replaced with today's. The floor itself stays at 80: 87.2% is one platform's number, and
rule 9 says a raise waits for a measurement, not a guess — the next one should come from a
CI run.

## An earlier round: RFC 9520 failure caching (`FailureCache`)

Shipped: a resolution failure is remembered and acted on. `FailureCache` in
`namespy/cache/__init__.py` is consulted by `resolve_steps` before any query leaves
the process and recorded at each place a lookup dies. `RecursiveResolver` owns one
(`failure_cache=`,
`--no-failure-cache` on the command line). A zone whose servers stopped answering is
keyed on the zone — that is what makes the next name beneath it cost nothing, and
what §3.3's parent-throttling means in this codebase — while an alias loop or a spent
hop budget is keyed on `(QNAME, QTYPE, QCLASS)`. Patterns worth reusing:
`test_failure_cache_resolver.py`'s `_drive(gen, responses)` for asserting the
*absence* of a query — it returns every event the generator yielded, so "nothing
left the process" is the absence of a `SendQuery` in that list — and
`FailureCache(time_fn=...)` for TTL behaviour without sleeping. That closes the last
P1 item in `docs/roadmap.md`, its RFC 9520 §3.1 row included: that ceiling is counted
per transport ("A resolver MUST NOT retry a given query to a server address over a
given DNS transport more than twice"), so a silent server costing one UDP datagram and
one TCP attempt is conforming — it just had never been pinned. `test_silence_is_tried_once_per_transport_and_no_further`
and `test_edns_refusal_and_silence_do_not_combine_into_three_attempts` in
`test_resolver_truncation.py` do that now. What remains in the roadmap is P2 and below.

## Earliest round: EDNS option TLV + per-server payload adaptation

QNAME minimisation shipped opt-in this round: probe walk + descent
integration (`resolve_steps` takes `qname_min`), probe-aware handling of
terminal classifications (a probe's NODATA/NXDOMAIN demotes and continues
per RFC 9156 section 3 step 4 instead of answering for the original QNAME),
budget degradation to full names, `--qname-min` CLI, probes marked in
`--trace`, CNAME chasing deliberately full-name. Patterns to reuse for the
rest of this section: `test_qname_min.py` for fake-server descent tests.

The remaining work, in `docs/roadmap.md` order:

1. **Wildcard synthesis** (RFC 4592 section 2.2) — names carry
   `is_wildcard` already; the closest-encloser proof and synthesized-TTL
   rule are missing, and until then answers from `*.example` zones are not
   RFC-identical.

Shipped this round: EDNS option TLVs, and the payload sizes they travel with.
`namespy/edns.py` owns the code/length/value records and the three option codes
worth an opinion: NSID (RFC 5001), COOKIE (RFC 7873), Padding (RFC 7830).
Requestor side, `add_edns(options=...)` writes them into OPT RDATA and
`--nsid` asks every server the walk touches who it is, printed as hex per
section 2.4. Resolver side, `_server_ids` records what each server answered and
`_payload_by_server` what it advertised, and `_advertised_payload` offers a
server the smaller of our default and the size it asked to be offered (RFC 6891
sections 6.2.3/6.2.4, floored at 512 — a responder may ignore a smaller CLASS,
so going below the historic default buys nothing). Server side,
`--advertise-nsid` gives the demo server an identifier, `_reply_options` hands it
out only to a query that asked with a zero-length NSID option (RFC 5001 section
2.2), and `_edns_options_or_error` answers a misformed option with FORMERR *plus*
an OPT — a FORMERR with no OPT is what section 6.2.2 reads as "no EDNS here",
which must not be confused with "EDNS here, bad option". Two decisions are
deliberate: a code nobody here models is ignored rather than refused (RFC 6891
section 6.1.2), while a misformed one is a wire-format error in either direction
— the parser raises instead of truncating, and on the query side that raise is
what becomes the FORMERR; and padding is never emitted over plaintext UDP at all
(RFC 7830 section 6), which is why the server declines a padding request rather
than honouring section 4. Patterns to reuse: `test_edns.py` for TLV and resolver
plumbing, `test_server.py`'s `make_server`/`answer_with`/`extended_query` for
responder-side tests.

Shipped since the last handoff: the bailiwick filter for out-of-zone glue
(RFC 5452 section 6). A referral's address records now reach an `SlistEntry` only
if their owner is the answering zone or a subdomain of it, or lies under the zone
the referral delegates — RFC 1034 section 4.2.1 makes a parent responsible for
below-cut glue and nothing else it volunteers is credible. Discarded glue leaves
the nameserver as a name that still needs an address, which the `NeedAddress`
sub-resolution obtains from the servers that are authoritative for it (RFC 1034
section 4.2.2). The filter lives in `classify`, so every consumer of a referral
inherits it. Tests: `test_resolver_classify.py` (discard / keep-below-cut /
not-lame-without-glue / per-nameserver), and the two-hop descent in
`test_resolve_steps.py` now walks the sub-resolution instead of believing the
volunteered address.

Definition of done for any of these: focused tests + full suite green under
`-O`; roadmap row flipped in the same commit; README/CHANGELOG updated if
the gap list changes; ratchet coverage if it moved.
ved.
