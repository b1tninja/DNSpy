# Strategy — from RFC core to the reference DNS toolkit

The completeness matrix is [`roadmap.md`](roadmap.md); this document is *why*
the next rows are ordered the way they are. It distills a landscape survey
(tool ecosystems, operator practice, attack research — October 2026) whose raw
evidence lives in `docs/research.md`, a gitignored working note: claims there
quote other projects' trackers and age faster than a roadmap row should, so
only decisions cross into tracked prose, and strategy rule 8 (verify every
citation against the document body) still applies before any of it reaches
code.

## The constitution (unchanged by this plan — everything below must respect it)

1. **The core is the RFC implementation.** `namespy/` stays codec, walk,
   validation, stub transports, server gates, zone serving, EDE vocabulary:
   protocol-correct, asyncio-native, dependency-free. New core code only when
   a specification defines the behavior — or when an ordering rule with no
   spec earns explicit convention-labeling, the `rbl.py` precedent.
2. **Composition gets its own tier.** `namespy.apps.*` (stdlib-only) holds the
   reusable assemblies — Forwarder, RouteTable, sinks — that *only* compose
   core pieces. The import line says "I am assembling," which is the
   distinction the project cares about.
3. **Extract on second use.** A pattern graduates from `examples/` to
   `namespy.apps.` when a second user appears — `_reversed_labels` (increment
   Z) is the precedent, stated rather than assumed.
4. **Positioning: correctness and instrumentation, not throughput.** The
   incumbents re-implement broken codecs (dnspython's 2.9.x changelog is a
   list of parser-bug fixes), lie about negative answers, ship rate limits
   that throttle the wrong thing, and do enumeration with DNSSEC denials
   opaque. namespy does the wire right and *says how it knows* — every answer
   carries provenance (walk vs cache vs hosts vs policy, validated or not).
   The declared non-race: raw q/s (massdns' C+epoll figure), DoQ/DNSCrypt
   without a QUIC dependency, GUIs.

## The three tiers

| Tier | Home | Contents | Rule |
|---|---|---|---|
| Core | `namespy/` | today's modules + the engine seam (policy) + `apps` namespace | RFC-cited or convention-labeled; honesty rule applies to every row |
| Apps | `namespy/apps/` | lookup/stub facades, Forwarder, RouteTable, ValidatingStub, sinks | composes only; no new protocol surface |
| Examples | `examples/`, `docs/recipes.md` | one runnable script per use case; recipes quote example docstrings so docs cannot drift (`blocklist.py` precedent) | configures apps/core; never restates library logic |

## Interface grammar: one engine, three drives

Every protocol object is an `asyncio.Protocol`, so the whole public surface is
loop-bound. The fix is adapters over the single async engine — never parallel
implementations (`_reply` as sole egress door, applied to API drives):

- **await** (native) — unchanged.
- **blocking** — a facade thread owning a private loop; `run_coroutine_threadsafe`
  marshals calls. This fixes the nested-loop trap by construction: a blocking
  call from inside a caller's running loop must work, and each wrong turn's
  error is named in docs rather than papered over.
- **callback** — plain callables (`on_done(future)`), no third-party promise
  type (dependency constitution); a raising callback is logged, never allowed
  to kill the engine — the `_ResponderFailed` rule crossed to the client side.

Hard parts owned up front: thread affinity (sockets and session pools stay on
their loop), timeout parity across drives (one policy, one error type either
way), one-shot vs resident objects (held DoT streams per RFC 7858 §3.4 are why
a context-managed `Stub` beats a fresh engine in any 1000-question loop), and
the server's blocking drive documented honestly: handlers run on the loop
thread, so sync handlers are microseconds of pure computation by contract —
deferral gets added only when an example needs it.

## The roadmap (increments AB onward; each ships with a roadmap row + tests + example in the same commit)

**Phase 1 — the seam and first apps.** Engine (loop-thread adapter; its test
suite pins the nested-loop case, timeout parity, callback isolation);
`apps.lookup` one-shot blocking API with provenance line; `apps.stub` resident
three-drive client with sync+async context managers; README's library section
gains the one-liner.

**Phase 2 — forwarding and interception.** `apps.routing.RouteTable`
(longest-suffix match, zone-match means no fallback — convention-labeled after
its citation pass, EDE-22 on silence); `apps.forwarder.Forwarder` (the
server+stub relay that already composes today, now named: stub.py's forward(),
server.py's AA-clearing and EDE-22 silence — zero new core code is the
composability proof); interception examples (bind() redirect, block-with-EDE-17,
hosts-file serve adapter, client-side hosts honesty line); `docs/recipes.md`
seeded.

**Phase 3 — research instruments, flagship order.** Validating stub assembly +
RFC 8509 sentinel self-check (the delv/pyunbound counter-position: four-state
verdicts, aggressive NSEC, DoT/DoH); bulk resolver with real per-upstream
egress token buckets and DNSSEC-denial-aware wildcard filtering (what no Go
brute-forcer does); audit battery (AXFR attempt gated on U6's transfer leg,
version.bind, NSID, ANY per RFC 8482, NSEC/NSEC3 walk with opt-out and RFC 9824
conclusions, CAA upward walk honoring flag-128/issuewild, TLSA/DANE against a
real `ssl` chain, SVCB §2.4 selection explained); tunnel/beacon statistics over
QueryLog NDJSON (ATT&CK T1071.004 shapes; RFC 9076 §8 is the rationale);
honeypot profile (refusal + first-seen store + tarpit-as-refusal, argued
against the RRL non-goal when it ships) and RDAP cross-check via RFC 9224
bootstrap with DNS↔RDAP NS-set consistency.

**Phase 4 — surface.** Entry-point dispatcher (`python -m namespy.forwarder`;
bare `namespy example.com` unchanged; the increment-Z bareword `rbl` rewrite
was this trying to be born); resolv.conf/hosts/search-ndots readers in apps
only, opt-in with traceable candidate order; one canonical NDJSON record across
all outputs (query, transport, server, rcode, flags, TTL-with-expiry, verdict,
provenance, origin rung).

**Deferred / declined with reasons:** raw-throughput race; DoQ/DNSCrypt;
ECDSA/Ed448 beyond the crypto extra's scope; visualization; RRL/flood
mitigation (loopback-fixture stance, reopened only by the honeypot row's
argument); C-DNS (RFC 8618) stays a documented pointer, not a format to own.

## How this document and roadmap.md stay in sync

- Every increment that ships an apps/example capability adds or crosses a
  **third-horizon row** in `roadmap.md` (W-Z series), with the same honesty
  rule: ✅ requires a named test that would fail on regression, and
  convention-labeled anchors where no RFC exists.
- A row may not claim an RFC anchor this file sketched until it has passed its
  own citation verification against the document body — several survey-time
  anchors here are leads (flagged as such), not settled citations.
- When a phase closes, this file's roadmap section is rewritten to match
  reality rather than annotated; drift in a strategy doc is worse than its
  absence.

