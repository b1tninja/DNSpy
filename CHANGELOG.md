# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project intends [semantic versioning](https://semver.org/spec/v2.0.0.html), though
nothing has been tagged or published yet, so `master` is the only version.

## [Unreleased]

### Added

- Compact Denial of Existence, validator-side: RFC 9824 lands with a correction to
  this project's own deferred-work list (the row that queued it as "the compact
  NSEC3 digest formats are themselves RRs" — 9824 adds no RR format; it adds
  **NXNAME (128)**, a Meta-TYPE whose bit in the type bitmap of an NSEC/NSEC3
  record *matching* the queried name is the zone's signed assertion that the name
  does not exist at all, delivered across a NODATA-shaped, minimally-covering,
  online-signed proof (§2, §3.1, §4 — the §7.1/§7.2 amendments to RFC 4034 §4.1.2
  and RFC 4035 §2.3 are exactly the two rules this codebase already enforced, and
  the increment honours both: the NXNAME bit is read only on the matching record,
  the matching record's existence-in-zone implication is what §5.1's branch
  replaces). The registry work is three lines: `DnsRType.NXNAME`, EDE code 30
  ("Invalid Query Type", §9 Table 3, taken as the §3.5¶3 MAY beside a served
  FORMERR), and `EDNS_CO_BIT` at OPT flags bit 14 — the last of these outranking
  a years-old local claim that bit belonged to an EDNS CD flag, which the live
  IANA registry has never carried (see *Changed*). `nsec.py` grew
  `record_asserts_nonexistent` and `record_is_compact_denial` — §3.1¶2's
  "RRSIG, NSEC and NXNAME, nothing else" for NSEC, §4¶6's "NXNAME as the sole
  entry" for NSEC3 — and the successor forms (§3.1¶2's null-label prepend,
  §4¶5's hash-plus-one) are tested where they bite: `name_between` finds nothing
  between a name and `\0.name`, nothing between a hash and the hash plus one, so
  the empty span §6¶3 leans on is proven rather than quoted, RFC 9824 §4¶8's
  worked example (`a.example.com` → `H64KFA4P1ACER2EBPS9QSDK6DNP8B3JQ`, next
  `…JR`) pinning the arithmetic. `validate_denial` grows `via_compact` on its
  verdict (the `via_opt_out` pattern) and a `co_signaled` parameter: under
  NOERROR the signal is extracted from the matching record the §8.5/§5.4¶3 proof
  already selects — a malformed pairing (NXNAME beside a real type) degrades to
  *no signal*, the answer standing on QTYPE's absence while this resolver
  declines to restore anything from a bitmap that contradicts itself — and under
  NAME_ERROR with CO the §5.1¶3 shape is accepted (NODATA proof wearing RCODE 3,
  bit required) while NXDOMAIN over a matching record *without* the bit is
  refused as unproved rather than believed, and CO stays inert against the
  conventional covering proof, which §5.1 demotes nowhere. §6¶3's two bans are
  kept where each lives: the walk caches a compact denial — restored NXDOMAIN
  included — as a name-level entry, never the cut-capable `Nxdomain` shape, and
  `aggressive.py` discards any proof bundle carrying the NXNAME bit before the
  synthesis geometry reads it, with a differential test (one bit, `None`) for the
  `www TXT` NODATA that would otherwise be fabricated beside a name declared
  gone. Asking for any of it is opt-in: `--compact-answers` sets CO alongside
  DO (`RecursiveResolver(compact_answers=True)`; §8¶2 is candid that CO asks
  zones to sign on demand), but the walk honors a signal it never requested,
  because what vouches for it is the signature. And §3.5's refusal of the
  question itself is enforced at every door this package owns: the CLI's type
  parser exits with a sentence on `NXNAME`/`TYPE128` (it parses the number
  precisely so the refusal can name it), `resolve_steps` raises rather than
  walking (§3.5¶2's "MUST NOT ... attempt iterative resolution"),
  `StubResolver.forward` raises rather than forwarding, and the demo server
  answers FORMERR with EDE 30. The `CompactDenial(name, restored)` event
  separates §5.1's zone-restored NXDOMAIN from the NOERROR shape whose only
  denial is the signed bit — the distinction the packet itself no longer
  carries. `tests/test_compact_denial.py`, 23 tests, reusing the signed fixture
  tree through `test_dnssec_wiring`'s harness. Not done, deliberately: the
  serving side of compact answers (the fixture zone signs nothing — online
  signing is out of this repo's scope) and §5¶2/§5.1¶5's downstream-querier
  RCODE surgery, which belongs to a recursive *server* product and namespy
  serves no downstream.


- IDNA2008 at the boundary: `namespy/idna.py` turns a name a human typed into a name the wire can carry, so `namespy münchen.de` works and `DomainName.from_unicode` gives library callers the same door that the CLI walks through (RFC 3492, RFC 5891, RFC 5890 §2.3 — the roadmap's "callers must pre-encode today" line, closed). The punycode codec is a line-by-line transcription of RFC 3492 §6.1-§6.3 with §5's parameters, and the test file says so: all eighteen §7.1 sample strings are pinned in both directions, the §7.2 traces check §6.1's bias values (21 … 84 … 90) and the insertion-order lesson of example L, and example S pins the delimiter-after-literals rule at the codec level where it lives — IDNA proper never encodes a pure-ASCII label, which is also why an A-label that decodes to one is a Fake A-label (RFC 5890 §2.3.1 ¶5) and gets rejected. §6.2's failure modes are §6.2 ¶3's completeness argument, so the decoder distinguishes them by name — unexpected end of input, no-digit-value character, non-ASCII encoded string, and the three overflow checks done as §6.4 ¶2's `B > maxint − A (div C)` comparisons against a 26-bit maxint, §6.4 ¶1's own bound for IDNA labels read through verified erratum 265 ("the maximum value of an integer variable" — in Python that is a choice, and the spec names the width). The decoder is case-insensitive over digits (§5 ¶6) and emits lowercase (§5 ¶6 + RFC 5890 §2.3.1 ¶4). Above the codec sits the label protocol: U-label candidates pass NFC (§4.1/§5.4), the hyphen restrictions (§4.2.3.1), the leading-combining-mark test (§4.2.3.2), and the table-decidable subset of the character tests — unassigned (`Cn` in *this Python's* Unicode, exactly §5.4 ¶9's semantics) and a conservative DISALLOWED slice (controls, separators, private use) — while RFC 5892's derived tables stay a stated, cited deferral that §5.4 ¶13 explicitly legitimises for a lookup application: "if they are registered, they are presumed to be valid". A-labels arriving off the wire are lowercased, decoded, tested, and — §5.3 ¶1 — must re-encode to exactly what they came as or are rejected; the presentation direction, `to_unicode`, answers zone data's fakes with the lowercased label as written rather than an exception, because §5.3 ¶2 asks only that a bad label be recognized as not-one. `DomainName.from_unicode` folds ASCII case by default — the DNS's own equivalence (RFC 5890 §2.3.2.4), deliberately ASCII-only, so `MÜNCHEN` still punycodes to the label for `mÜnchen` and not the one for `münchen`, and `map_ascii_case=False` gets the strict IDNA2008 reading that maps nothing at all; the CLI's walk and stub entry points both use the folded form and answer nonsense with one sentence on stderr instead of a traceback. 78 tests in `tests/test_idna.py`. Also in this pass: the priority table in `docs/roadmap.md` caught up with the feature tables it had drifted from — wildcard synthesis (4592), DNSSEC validation, serve-stale (8767), and walk-side TCP reuse (7828/9210) are all struck through as shipped, as they have been for three increments.

- The SVCB half of opportunistic encryption: `--dot-authority` now asks RFC 9461's question before RFC 9539's. Before the walker first probes an authority address over TLS, it resolves `SVCB` at `_dns.<NS name>` (Port Prefix Naming, §3; `_9953._dns....` for a non-default binding, §3.1) and probes the port the answer names — §4.2¶1's 853 when the record states none. `namespy.opportunistic.learn_dot_endpoint` runs RFC 9460 §3's selection procedure (via the existing `select_records`) over a supplied fetcher, so the whole policy is testable over canned records: alpn must carry `dot` (§4.1), an explicit `port` is honored unless it sits on the confusion-risk list — FETCH §2.9's bad-ports enumeration with 443 argued back in, since 9461 itself names 443 as DoH's default and TLS payloads belong at a TLS port (§4.2¶3-¶4, auto-mandatory §4.2¶2) — a foreign TargetName is accepted only when an ipv4/ipv6hint vouches for the very address being probed (§4.3, §6¶3), AliasMode chains are followed up to five hops (§2.4.2¶10's MUST, the spec's own `ns.example` example as the test), and the answer's minimum TTL bounds how long the verdict is remembered. The verdict memo is keyed by (name, address), RFC 9539 §4.2's per-IP discipline applied to discovery, and misses are remembered briefly so a silent authority costs one walk, not one per query. Discovery never vetoes encryption: an absent, incompatible, or forged record leaves the blind 853 probe in place, because the record arrives over the very channel it describes (§6¶2) and proves less than a handshake does — and the discovery walk itself runs cleartext-only under a guard flag, which both bounds the recursion and forecloses a deadlock between the probe and the lookup that configured it. `RecursiveResolver(opportunistic_discover=False)` keeps the 9539 behavior pure. 21 tests added to `tests/test_opportunistic.py` (the policy over pages of records — default and explicit ports, the decline of 6667, DoH-only records, hints, priorities, aliases, caps — and the seam's memoization, guard, and per-address keying against a page-table walk).

- Opportunistic encryption of the recursive-to-authoritative leg (RFC 9539 §4): `--dot-authority`, or `RecursiveResolver(opportunistic_dot=True)`, makes the walk try DNS over TLS to port 853 of every authority it queries and *remember what happened*, per the document's bolt-on design. `namespy/opportunistic.py` is the whole policy as pure arithmetic — Table 2's per-(transport, address) connection-state record, Table 1's parameters (persistence 3 days, damping 1 day, handshake timeout 4 s, read per-protocol as verified errata 7831/7832 correct the pseudocode to say), §4.6.1's rule for when cleartext may still speak, §4.6.3's gate on starting a new connection, and the §4.6.4–6.7 success/failure/clean-close transitions. `Resolver` acts on it: an established session rides alone; a fresh success silences cleartext while persistence holds, with §4.6.5's fallback to Do53 the moment the encrypted leg fails; a first sighting races both transports, and — §4.6¶5's explicit departure from Happy Eyeballs — the losing encrypted initiation keeps running in the background so the *next* query inherits the verdict. The TLS posture is the spec's, and deliberately the inverse of the stub's strict RFC 7858 client: any certificate accepted (§4.6.3.4's MUST — rejecting would force the cleartext fallback that leaks), no SNI (§4.6.3.3¶4), ALPN `"dot"` offered (§4.4¶2). Failure keeps its taxonomy: refusals and stalls damp for a day (§4.6.5/§4.6.3¶4), a peer's clean close retries promptly (§4.6.7), and mismatched or malformed answers discredit the stream they arrived on (§4.6.9¶12, the same reading-position argument as the cleartext pool). `edns-tcp-keepalive` is honoured on this leg too (RFC 7828); deferred with reasons at the module's door: DoQ (§4.4's second SHOULD — `aioquic` again), session resumption (asyncio's client exposes no seam for presenting a ticket), and padding (the RFC 8145 §5 row). The SVCB-discovery half of the roadmap row — `_dns.<name>` per RFC 9461 §4 upgrading the blind probe — is the next increment. Off by default: §4.1¶1 makes the whole exercise OPTIONAL, and it opens new egress. Tests: `tests/test_opportunistic.py` (21 — the policy clause-by-clause with both errata proven as per-protocol formulas; the race, ride, damping, §4.6.7 retry, keepalive-0 and failure paths against the loopback DoT fixture, with no-SNI and ALPN-negotiation proven from the server's own TLS object and the fixture's untrusted self-signed certificate doubling as §4.6.3.4's witness).

- The two remaining halves of DNS over TCP: reuse on the walk's own fallbacks, and a server side that answers back (RFC 7766 §6.2, RFC 7828 §3.3, BCP 235). `Resolver._query_tcp` — the fallback every truncation and timeout lands on, shared by the walk and the stub's cleartext transports — no longer opens a connection per query and closes it: one held `_Session` per `(host, port)` rides every later exchange (RFC 7766 §6.2.1¶1's reuse, §6.2.2¶1's one-connection rule enforced by the session's lock), the server's offered `edns-tcp-keepalive` TIMEOUT arms its idle timer (§3.2.2¶2), a 0 drops the session on the spot (¶3), silence rides the conservative 30 s, and a stream that died between queries is reopened invisibly with one retry (§6.2.4¶2) — the same session shape `dot` already kept, now hoisted from `namespy/stub.py` to `namespy/resolver.py` because both legs own pooled streams. `AXFR` is the documented exception (§6.2.2¶1 counts transfers their own connection) and stays one-shot; a mismatched answer on a shared stream retires the stream it arrived on, because a stale response means the reading position drifted. On the answering side: `DnsStreamServer`, a per-connection TCP front for the demo `DnsServer` — the framing, the FORMERR-on-unparseable-message that spares the stream, the zero-length frame that ends it, pipelined queries processed concurrently and answered in arrival order (§6.2.1.1¶4), and an idle close on the configurable `DnsServer(tcp_idle=30)` that RFC 9210 §4.2¶4 asks software to provide, reset only by complete messages as §6.2.3¶3 demands against the slow-read trick. The keepalive conversation is answered honestly — `keepalive_option(timeout)`'s new server form advertises exactly the number the connection enforces (§3.3.2¶1's MUST; `None` stays silent and lets clients fall back per §3.2.2¶4; 0 refuses and closes; a client's draft-era 0-hint gets its last answer advertised at 0, because a dying connection associates no idle time with itself), UDP keeps ignoring the option exactly as §3.3.1¶1 requires, and `_reply`/`_error`/`respond_to_packet` gained the `StreamChannel` send-seam that makes one responder pipeline serve both transports without either knowing about the other. `--serve` now binds TCP beside UDP — BCP 235 updated RFC 1123 to make both non-optional, and a demo answering only UDP would demonstrate the failure the document was written about. Tests: `tests/test_stream_reuse.py` (8: reuse, one-connection concurrency, offered-timeout hold, 0-refusal, silent reopening after a mid-queue death, mismatched-answer discredit, AXFR one-shot, pool close) and `tests/test_server_stream.py` (12: advertising the enforced number, configured numbers, silence, no-OPT queries, both 0 paths, FORMERR-survives/zero-length-dies, the idle timer observed from the clock's reset point, pipelined concurrency measured, UDP's MUST-ignore, and the package's own stub and front completing one keepalive conversation end to end).

- The transport tests can no longer hide from the coverage floor: the loopback TLS fixture is a checked-in static self-signed certificate under `tests/certs` (a handshake needs no generator -- `ssl` is stdlib) and the CI test matrix installs the pure-Python `doh` extra, so every DoT and DoH line runs in all four matrix jobs. The DoH commit's CI was the lesson: its transport tests skipped everywhere outside the extras job, `namespy/doh.py` measured 15% in the matrix, and the 80% floor failed the commit at 78.76%. The import probe in `namespy/doh.py` also stopped rebinding `h2` to `None` when the extra is absent -- every reference is guarded by the `H2_AVAILABLE` check, and the rebinding was the unused-ignore the lint job caught.

- DNS over HTTPS for the stub (RFC 8484), in whichever HTTP the server negotiates. `--stub-transport doh` / `Upstream(transport="doh")` forwards over HTTPS to the §2.1 default port 443 through `namespy/doh.py`: `_DohSession.exchange` accepts nothing but a 2xx `application/dns-message` whose questions echo the ones sent (§4.2.1's refusals said rather than guessed around), POST carries §4's wire bytes and GET fills §4.1's `{?dns}` template with base64url-no-padding (§4.1.1¶5's own encoded message is a golden test), and every query leaves with ID 0 because HTTP, not the DNS header, correlates the exchange (§4.1¶8). The HTTP itself is decided by ALPN (§5.2): HTTP/2 via the new optional `h2` extra (pure-Python, so the `doh` extra is an acceleration, never a requirement) multiplexes one query per stream over a single held connection (§4.2¶3) with the flow-control bookkeeping that makes a DNSSEC-sized answer deliverable — 1 MiB stream windows via SETTINGS, an explicit connection-level WINDOW_UPDATE (SETTINGS alone is per-stream only, RFC 7540 §6.9.2), DATA acknowledged as it buffers, bodies chunked to the peer's `max_frame_size`; HTTP/1.1 via stdlib is one exchange at a time on a kept connection, conservatively idled at 30 s because RFC 7828's option does not travel on HTTP. The dot machinery generalised rather than duplicated: `_ask_dot` became `_ask_stream`, the dead-upstream memory became transport-neutral, and a multiplexed session skips the serial lock every other session takes. `Upstream` gains `path` (`1.2.3.4:443#dns.example/dns-query`, the §3¶1 configured template) and doh's default 443; §8.1¶1's authentication is the same BCP195 door as `dot`, entered with §5.2's ALPN offer added. Closes a bug the dot increment shipped: `--stub-transport dot` forwarded to port 53, because `dataclasses.replace` after `Upstream.parse` re-ran construction with the port the udp default had already pinned — `parse` now takes the declared transport, with a test naming the trap. `tests/test_stub_doh.py` (17) runs against real TLS servers on loopback, ALPN-decided: the POST and its headers observed server-side, ID-0, sequential reuse and three-way concurrent multiplexing on one connection, a 90 KB answer proving the window bookkeeping, the http/1.1 round-trip and idle-timer, GET's golden vector, 400/foreign-media/foreign-question all refused to silence, the dead-upstream memory, path-and-port parsing. CI's extras job installs and exercises `[crypto,doh]`.

- DNS over TLS for the stub (RFC 7858), and the keepalive that paces it (RFC 7828). `--stub-transport dot` / `Upstream(transport="dot")` forwards over TLS to the §3.1 default port 853 (an agreed alternative "MUST NOT be port 53" — so 53 stays cleartext by construction), with the length-prefixed framing §3.3¶1 shares with RFC 7766 and the single-write preference both documents state — now one `_stream_exchange` on the base transport, used by the walk's TCP fallback and the TLS sessions alike. Authentication is the door, not an option: `dot` requires the name to authenticate (`1.2.3.4:853#dns.example.net`; BCP195 via `ssl.create_default_context`, whose trust an application extends through the documented `_tls_context` seam), and this build declines §4.1's unauthenticated profile outright — privacy without identity on a path that can be attacked feeds a stub any answer, and cleartext transports already exist to say "I don't care" honestly. Reuse is §3.4's: one session per upstream lives from connect to idle-timeout, shared by concurrent queries through its lock (a waiter takes the connection, not a rival handshake), and its idle life is RFC 7828's conversation — the client's empty request form (§3.2.1¶4's MUST) rides every stream query, the server's offered TIMEOUT becomes the close-before deadline (`_idle_seconds`: honoured, floored at 2 s, defaulted to the §6-flavored 30 s), 0 closes immediately (§3.2.2¶3), and absence means RFC 7766 behavior (keep on the conservative default; the option parse reads the draft-era 1-octet form too). §3.1¶4's memory: a TLS refusal, timeout or handshake failure remembers that upstream for an hour — the paragraph's own "such as one hour" — and a live answer clears it; a session that merely died idle re-opens invisibly, one retry. `edns.py` gains `KEEPALIVE_OPTION_CODE = 11`, `keepalive_option()`, `keepalive_of()`. `tests/test_stub_dot.py` (14) runs against a real TLS server with a generated certificate: RD-and-intact over TLS, the empty option on the wire, sequential and concurrent reuse on one connection, 0-closes / offered-kept / floor-held / default-held, name mismatch fails closed and stays remembered, 853 defaults, the option's whole parse table.

- The stub resolver — the forwarding mode RFC 1034 §5.3.1 describes in one sentence ("All that the remaining stub needs is a list of name server addresses that will perform the recursive requests"), and the prerequisite the roadmap's encrypted-transport rows named as missing. `namespy/stub.py`: `Upstream` (address literals only — resolving a resolver stays the configuration file's bootstrap problem; `parse` reads `1.0.0.1`, `1.0.0.1:5353`, `[2606:4700:4700::1001]:853`) and `StubResolver`, which drives the walk's *own* send path — `Resolver.query`, its UDP→TCP fallback, its answer-matching — at a configured server instead of a delegation tree, for which the base class gained the receive plumbing (`datagram_received`, the v6 bring-up) it had only assumed, plus a `port` and `force_tcp` on the seam. Forwarding fidelity: `RD` set on the way out (§4.1.1's "directs the name server to pursue the query recursively"); the answer returned exactly as it arrived, RA and AD and TTLs included; **REFUSED read as §4.1.1's optional recursion declining this upstream** — the next is asked, and only an all-refused list returns the refusal; **SERVFAIL taken as an answer** — that upstream did the work, the name failed, fanning out buys delay not news; `client_cd` copies the CD bit per §3.2.2's arrangement. The walk is untouched: same defaults (port 53, no forced TCP), existing tests unmodified bar one stub signature. CLI: `--forward UPSTREAM` (repeat for backups, tried in order), `--stub-transport udp|tcp`, a composed SERVFAIL when nobody speaks, conflicts with `--serve`/`--mqtype` said plainly (`namespy --forward 10.1.1.1 example.com`). This is the transport seam RFC 7858 (DoT) and RFC 8484 (DoH) now land on as `Upstream` transports rather than as new resolvers. `tests/test_stub_resolver.py` (13) + five CLI tests.


- Wildcard synthesis from the cache — the positive half of RFC 8198 §5.3, the other half of the two the aggressive round opened. A validated wildcard-expanded answer now files its *template*: `_write_cache` reads the covering RRSIG's Labels field (RFC 4035 §4.5¶4 named this deduction — "by using the RRSIG record, it is possible to deduce that an answer was synthesized from a wildcard ... could store this wildcard data and use it to generate positive responses to queries other than the name for which the original answer was first received"), rebuilds the signed name with `signed_owner_name` — the same undo-the-expansion arithmetic §5.4¶3 reads on the NSEC side and `_validate_wildcard` read at judgment time — and stores the RRset at the wildcard's own owner, data and signatures together, stamped. The serving side (`synthesize_wildcard`, same module as the denials, same `--aggressive-nsec` knob) requires both of §5.3's halves exactly as written: the corresponding wildcard record in the cache — the deepest ancestor of QNAME with a cached entry at its wildcard node, §3.3.1's "no search for an alternate" read from the resolver's side, so a present-but-unusable entry falls back to the network rather than climbing to a shallower wildcard — and the determination that the name "would not exist without the wildcard match", which is the §5.3.4 (NSEC) / §8.8 (NSEC3) closer-match proof run whole against a cached, validated, signature-live denial bundle *from the template's own zone* (the span test's thinness is sound precisely because an NSEC3 covering the next closer proves every intervening name absent by tree closure; Opt-Out spans are refused, they prove a DS absent, not a name). The presented answer is the authority's own shape — records at QNAME under the wildcard's signature, its Labels field carrying the match's proof — with the TTL bounded by the template's remaining life; RFC 9077 §3.4's three-hour cap governs negative information, and a synthesized positive is data. Gates as before: bogus answers file nothing, unvalidated templates never serve, expired signatures end the evidence before the TTL does (the poisoned-long-TTL row again), CD clients see the wire, non-validating readers get the answer without AD, and nothing is written back. `WildcardSynthesis` names the template in the trace; SOA and wildcard-NS never template (RFC 4592 §4.1¶1, §4.2¶3 — "can never be a source of synthesis", and undefined semantics are not synthesized). The fixture zone grew a `*.y.zone.test.` TXT branch on its chain's wrap edge, and `tests/test_wildcard_synthesis.py` (16) proves it: sibling and grandchild names answered with zero queries, every refusal re-asks.

- Serve-stale on upstream failure (RFC 8767; signal per RFC 8914 §4.2). Two layers, as the document splits them: the cache gains §5¶11's maximum-stale timer (`stale_ttl`, 0 = today's discard-on-expiry), retaining an expired row inside the window without ever letting `get` call it live — and a `stale()` door that hands out only what is expired-but-younger-than-the-window, retiring on sight what is not (LRU stays honest: stale rows deliberately lose eviction contests, §6¶3). The walk answers from that door at exactly the two seams where refreshing has failed — the out-of-servers exhaustion (§7¶1's "only when refreshing has failed", the outage the document exists for) and RFC 9520's remembered-failure block (§5¶7's recheck window: "the cache may be immediately consulted for stale data") — and nowhere else: a data-level failure (alias loop, hop budget, validation refusal) still fails honestly. The answer is rebuilt, never edited: §4¶4's MUST re-TTLs every record greater-than-zero at the recommended 30 (which doubles as the client's retry rate-limit, §6¶6), AD never rides (§3.2.3's claim is present tense; the stamp says *verified then*, not *authentic now*), the `stale_answer` marker becomes EDE 2 on the wire — the signal §9's rejected EDNS option never needed, since 8914 built the general door — and the trace and CLI say so plainly. CD clients may take the stale answer (it is a cache read, not an inference; their own validator judges the bytes, §10¶1's accepted risk). `--serve-stale [SECONDS]` (bare = 86400, the low end of §5¶11's 1–3 days) opens the window and the door; off by default — trading correctness for reachability is an operator's call. `ServeStale(name, age)`; tests: `tests/test_serve_stale.py` (17) plus the serve-side EDE-2 test in `test_dnssec_serving.py`.

- Chain records in the cache — the DNSKEY and DS material a secure verdict verified becomes §4.5¶1's atomic entry like any other answer (RFC 4035 §4.5, §5.2¶6; TTLs and signatures as one unit; RFC 8198 §7's "until the effective TTLs or signatures expire" read once more). The validation-pipeline row's last clause — "chain records live in a per-lookup store rather than the cache — revisit if wildcard synthesis wants reused proofs" — is what this closes: the walk already fetched every chain leg §5.2¶6's verdict demanded and verified it end to end under its own anchors, so the bytes need no second fetching while their entry lives. A lookup that ends secure files each DNSKEY and DS RRset it saw — data and covering RRSIGs together, min-TTL atomic expiry on the cache's clock, `validated` stamped because this resolver verified them, never merely resolved — and the next lookup's hint loop consults the cache before the wire: a stamped entry whose every signature still covers the moment feeds the validator's store and traces as `ChainFromCache`, the only place an otherwise-invisible absence of a query appears. Both gates are load-bearing. Unstamped material (a client's own DNSKEY query that merely answered) is not chain evidence — §4.3's states are this validator's answers, not the cache's — and the stamp licenses only the load: the validator re-verifies every byte against its own anchors as always. The signature-window read is the two-clock filter the aggressive round named: an entry alive by the cache clock can carry an RRSIG whose window closed (§9¶4's poisoned-long-TTL row), expiry is absence — re-fetch, ordinary walk — never Bogus: a cache that turned a live zone bogus on its own stale signature would be the attack doing the resolver's work. Bogus and unvalidated verdicts write nothing; a fresher stamped entry is never aged out by a re-verification of the same bytes. Verified against the fixture tree: a second name in the same zone climbs the whole chain from the cache — zero helper queries, secure verdict, three network packets instead of six (`tests/test_chain_cache.py`, 7). This is the unlock the roadmap's wildcard-synthesis row was waiting on.

- Aggressive NSEC caching — denials synthesised from proofs already in the cache (RFC 8198 §5, §7, §9, Appendices A–B; TTLs per RFC 9077 §3.4). RFC 8198 §7 rewrote RFC 4035 §4.5's "it seems prudent for resolvers to avoid ... synthesizing new data on their own" into "once the records are validated, DNSSEC-enabled validating resolvers SHOULD use ... NSEC/NSEC3 resource records to generate ... negative responses until the effective TTLs or signatures for those records expire", and `namespy/aggressive.py` is that sentence's negative half at the place Appendix A ¶3 says to run it: after the exact-key lookup and the RFC 8020 cut miss, before any query. What it reads is the second lookup the cache never had — `DnsCache.denial_candidates` (memory and SQLite, the base's `()` the documented fallback), because the NSEC that covers `dog.example` was cached under `albatross.example`, which is neither the name nor any of its ancestors. What it will do is bounded by the text gate by gate: only entries carrying this resolver's own fully-verified stamp (Appendix B ¶2 discards everything else); only a *complete* proof of the queried name, obtained by feeding the cached bundle back through the same response validators a live answer faces (RFC 4035 §5.4 whole for NSEC, RFC 5155 §8.4–§8.7 for NSEC3 — so an incomplete bundle triggers Appendix A ¶4's MUST-fallback and the network sees the query as though 8198 did not exist); Opt-Out spans deny nothing (§5.2¶3); a name below a delegation is not this zone's to deny — both closest-encloser walks already refuse an NS-without-SOA at the encloser (§8.3¶12, Appendix B ¶4 in intent), and the matching-record-at-a-cut shape NODATA could walk into gets the same check, with the text's own exception honoured: DS is the one type whose proven absence *at* the delegation point is the answer (§5.4¶5, §8.6). §7's "until the effective TTLs or signatures expire" is read in both halves — the entry's expiry and the bundle's RRSIG windows, the latter a timestamp check, not a re-verification, so the stamp-at-write doctrine stands; the synthesised answer's TTL is the evidence's remaining life, capped at three hours (§5.4¶2 as 9077 §3.4 replaced it; §9¶3's blast-radius reason), and nothing synthesised is written back — one proof, one entry. Appendix A ¶1's CD exemption travels with the knob, not the module: `--aggressive-nsec` (off by default — §9¶4: poisoned evidence suppresses a neighbourhood instead of one query when this is on, and must repeat the attack per query when it is not) never answers a CD client from synthesis at all. The synthesised packet is the denial's honest shape — SOA plus, under `--dnssec`, the proofs that prove it, AD only as the validator-instance rule already decides, never AA — and the `AggressiveDenial` trace event names the queried name beside the entry that vouched, which is the only place the two appear together: the proof's name need bear no relation to the question's. `tests/test_aggressive_nsec.py` (21). This round also corrects the previous rounds' "Next" lists: RFC 9908 is a certificate-enrollment document; the aggressive-caching specification is RFC 8198, and the roadmap row always cited it correctly.

- Trust-anchor knowledge on the wire — `edns-key-tag`, RFC 8145's option 14, as querier, copier, and silent responder (§4.1–§4.3, §7; RFC 4033 §2; RFC 4034 Appendix B). The codec (`key_tag_option`, `key_tag_lists`, `key_tags_of`, `MAX_KEY_TAGS` in `namespy/edns.py`) reads §4.2.2.1¶2's wire literally — own and client lists travel as *separate instances*, so the reader keeps instances apart and only the copier's flattened reading merges them — and takes §4.2.2.1¶3's recommended limit (§7¶3's "made up" tags are the published way to stall a rollover) at 32. The claim is the care: `Validator.key_tags_for` reads exactly §4.2¶3's two sources — anchors in either RFC 4033 §2 shape and the DS records the descent collected — because §4.2¶6's MUST NOT forbids more, and a tag lifted from an answer's own keys would launder a forged key's number into telemetry a zone operator acts on. The walk then plays its three roles: chain-fetch DNSKEY queries carry the validator's own list (§4.2.2.1¶1's SHOULD), a client's list is copied (§4.2.2.2) or, when the server validates and differs, forwarded as a second instance behind the own list in the section's example order (§4.2.2.1¶2), and the option rides nothing else — not the DS query (§4.2¶2's MUST NOT, honoured by a per-query `SendQuery.extra_edns_options` rather than a resolver-wide setting that could only leak), not the probe, and not the referral hops: §4.2¶3 describes "the KSK(s) of the zone *for which the server is authoritative*", which an iterative walk can point at only where the queried name is the zone itself, so a root merely routing a DNSKEY question never learns a neighbour's key numbers (§7¶2 explains what listeners infer). Outbound of the server, §4.3¶2's flat "A responder MUST NOT include the edns-key-tag option in any DNS response" is satisfied by construction — reply OPTs are built from the response's own news — and inbound, malformed instances are read as *no list* rather than FORMERR, §4.2¶7's "no action needs to be taken" being the closest instruction a document that asks a responder only to log provides. What was declined and why: §5's Key Tag Query (the `#kt` QNAME mechanism that makes a server subset its keys — a different tool often confused with this signal) and §4.2.2.1¶3's cross-query tag-combining MAY, which would need a store of clients' knowledge this server refuses to keep. `tests/test_edns_keytag.py` (17): codec shapes, honest claims, the hop gate, the two-instance forwarding, the DS-query refusal, and the responder's silence (`namespy/edns.py`, `namespy/validate.py`, `namespy/resolver.py`, `namespy/server.py`).
- The two open DNSSEC-serving questions, answered against the text rather than the default (RFC 4035 §3.1¶1, §3.2.1¶1, §4.1¶1; RFC 3225 §1¶3, §2¶1–¶5; RFC 8020 §2¶5). **DS is strip material at the client hop**: §3.1¶1 enumerates what a DO=1 query buys — "additional RRSIG, NSEC, and DS RRs" — and §3.2.1¶1's exception is written in *types*, so a DS is authenticating material unless the query named it; `namespy.server._CLIENT_STRIP_TYPES` adds DS for that one hop while `DNSSEC_SECURITY_TYPES` stays narrow for the walk, which consumes §3.1.4's referral-riding DSes as data and never emits them — the single constant had been wearing both coats, and 3225's §1¶3 definition (SIG/KEY/NXT) could never have adjudicated a set 4034 later redrew. The leak this closes is the narrow but real one: a DS arriving inside a non-authoritative answer taken as given would otherwise reach the clients RFC 3225 §2¶3 reports failing on unparseable records. **`serve --dnssec` stays the operator's call, and now says so**: §4.1¶1's MUST belongs to the security-aware *resolver* role and `--validate` implies the flag accordingly, but asking every upstream for octets the 512-byte ceiling was argued around (3225 §2¶1–¶2) is a deployment decision; off is a legitimate stance whose cost is now logged at startup (`server_dnssec=off|records|validate`) and stated in `--dnssec`'s help — a server that never asked can echo no proof, RFC 8020 §2¶5's condition sitting on this server's own triggering query. Three tests rewrite the pinning that had encoded the old DS answer: stripped at DO=0 with the recount, kept for a query naming DS, kept for a QTx naming it (`namespy/server.py`, `namespy/dnssec.py`, `namespy/__main__.py`, `tests/test_dnssec_serving.py` +3/−1).

- The positive half of validation — §3.2.3's "if and only if" now covers everything it names (RFC 4035 §3.2.3, §5.3.1, §5.3.4; RFC 4033 §5; RFC 9520 §3.4; RFC 5155 §9.2). A terminal `Answer` is judged the way a denial was, by the same fetch-hinted loop, but as a composite: `_judge_answer` enumerates every distinct (owner, type) RRset the response's Answer and Authority sections carry — RRSIGs are evidence not assertion, and DNSSEC types go unjudged in passing unless the client queried one — and the sections stand or fall together, because AD means "all RRsets," not "the one you asked about": one forged RRset poisons the whole response, one Indeterminate part defers the whole and lends its hint to the loop, an Insecure part caps it, and only an all-secure set is SECURE. What the half-crank could not see before now convicts: an answer *stripped* of its RRSIG inside a zone the chain proves secure is RFC 4033 §5's missing-signature Bogus — a walk that judged signatures only when present would have served a downgraded answer as merely unauthenticated, which is the attack §5 says Bogus exists to close. Bogus with CD clear is refused exactly as a denial's was (SERVFAIL + `dnssec_bogus` + EDE 6 + the §9520 §3.4 failure note, nothing cached); CD=1 delivers the forged RRsets raw, unasserted, un-noted, uncached. SECURE raises AD on the response and stamps `PositiveEntry.validated` — a new field with a new meaning: *fully verified*, `ad_worthy` rather than `secure`, because the stamp now answers two questions (may this answer assert AD on a later cache read; may a denial cut) and RFC 5155 §9.2¶1's Opt-Out refusal reaches both — so the denial stamp narrowed with it, and a next-closer that may hide an insecure delegation now neither cuts from cache nor speaks AD on a read, the conservative side of a check that demonstrably could not finish. The wildcard's closer-match proof is a closest-encloser proof like any other, and `validate_rrset` now surfaces `WildcardAnswerProof.via_opt_out` for it, the third flag nsec.py had been exporting unread. `_fetch_chain` became judge-generic (any thunk returning a verdict; the loop refetches and re-runs it whole), `classify` needed nothing — its `Answer` is terminal only when the alias chain lands, so CNAMEs accompanying a target are judged as part of the sections that carry them. `test_dnssec_wiring.py` (+10) scripts the signed answer bearing AD through the three-fetch chain, the cache hit asserting from the stamp and the anchorless reader not, forged and stripped signatures refused, the CD pass-through, the silent-keys zone leaving the answer served-but-unasserted, the proved-unsigned child answering Insecure after its chain, and the two-RRset composite poisoned by one flipped SOA signature; the validator fixture's Opt-Out knob reaches wildcard answers (+1) and SQLite carries positive stamps across the trip (+2) (`namespy/resolver.py`, `namespy/validate.py`, `namespy/cache`).

- The header's Authentic Data and Checking Disabled bits — the moment a verdict becomes protocol-visible (RFC 4035 §2, §3.2.2–§3.2.3, §4.6, §4.7; RFC 6895 §2; RFC 6840 §5.7–§5.8; RFC 5155 §9.2; RFC 9520 §3.4; RFC 8914 §4.7). `DnsPacket` now models AD (bit 5) and CD (bit 4): RFC 6895's reallocation shrinks Z to the one bit still reserved to it, pack and parse both moved to the registry's layout, and the CLI prints `ad`/`cd` again — with the header's own values this time, which is what their removal two rounds ago said could never be honest. The bits then acquire rules before anyone could wave them: the walk clears AD and CD off every response it *fetches*, because §4.6¶3 says a resolver MUST disregard them unless the channel is secure and plain UDP is not, so an AD this resolver returns is only ever its own; `resolve_steps(..., client_cd=...)` reads the initiating query's CD and stops interfering exactly as §3.2.2¶3 demands — a Bogus denial is delivered rather than refused, nothing is noted (§4.2¶2 waived the check; an unexecuted check is not a cacheable failure), and the CD lookup's data is not cached, because a validator that files unvalidated answers for its later non-CD clients is the opening the strip-a-signature attacker pays for, and §3.2.2¶5's raw-data promise must not become a poisoning door. With CD clear and anchors set, a Bogus denial is now refused where it used to only lose its stamp: the walk yields a SERVFAIL marked `dnssec_bogus` — never serialised, a note between the two halves of one recursive server, which the serving side reads to answer with RFC 8914 §4.7's EDE 6 instead of the generic 22 — keeps the forged evidence out of the cache where the RFC 8020 cut would spread it subtree-wide, and notes the failure, which RFC 9520 §3.4 turned from §4.7's MAY into a MUST: remembered *validation* failures carry a `dnssec` flag so suppression backs off repeat non-CD queries at §3.2's escalating TTLs while CD queries walk past them. `AD` is then asserted where a verdict actually exists: on the SECURE denial's response, on the cached answers read from a SECURE stamp (and never read by an anchorless resolver — §3.1.6¶3 forbids vouching for what you cannot check), and never on an Opt-Out proof — `ValidationVerdict.via_opt_out` carries RFC 5155 §9.2¶1's MUST NOT out of the geometry that earns it and `ad_worthy` subtracts it, one property so no caller can honour the rule halfway. `DnsServer._reply` copies CD verbatim (§3.2.2¶2's MUST) and gates AD on the client having signalled DO or AD (RFC 6840 §5.8), the legacy-middlebox rule; and `DnsServer._flags_match`, whose docstring had always named `AD` while the line read the old misnamed OPT property, now compares the bit it means — making an MQTYPE combination that promises DNSSEC validity behind an unassertive primary unmergeable rather than tautologically equal. `test_packet_wire.py` (+4) pins the bit positions both directions and the old-stack decode; `test_dnssec_wiring.py` (+5, one rewritten) scripts refusal-caching-suppression-rewalk, the CD collect-everything-and-claim-nothing pass, and AD at write, at hit, and at cut; `test_dnssec_validate.py` (+2) proves a denial through an Opt-Out next closer and loses only the bit; `test_dnssec_serving.py` (+4), `test_server.py` (+1), `test_resolver_e2e.py` (+2), `test_failure_cache.py` (+1), `test_cli.py` (+1) cover the egress pair, the EDE, the arrival clearing and the echo (`namespy/packet.py`, `namespy/resolver.py`, `namespy/server.py`, `namespy/validate.py`, `namespy/nsec.py`, `namespy/cache`, `namespy/__main__.py`).

- The wiring that made `NxdomainPolicy.VALIDATED` real (RFC 4035 §5.2¶6, §4.1¶1, §4.5; RFC 8020 §2¶3) — the walk now validates the negatives it receives. `resolve_steps(..., anchors=...)` files every response into one `DnssecStore` per lookup with the responding zone as origin, so a referral's piggybacked DS (RFC 4035 §3.1.4) joins the chain for free; a terminal NXDOMAIN/NODATA is judged by `namespy.validate` before its cache write, and an Indeterminate born of a *missing record* names the cure on itself — the new `ValidationVerdict.fetch_hint`, `(name, rtype, from_zone)`, offered once per triple — which the walk pays for with its own `SendQuery` effect, mid-lookup, of the zone that holds it (§5.2¶6's "MUST query the name servers for the parent zone for the DS RRset", capped by `_MAX_SEC_FETCHES` besides). The verdict is traced as a `DnssecVerdict` event before the denial it judges (chain queries carry a `helper` flag; `--trace` marks them `(dnssec)`), and a SECURE one is stamped into the cached `NegativeEntry.validated` — persisted through SQLite by a column migration that reads every pre-existing row, honestly, as unvalidated. `NxdomainPolicy.VALIDATED` now cuts on that stamp and nothing else; its door refuses only what it always should have, the policy without trust anchors. `RecursiveResolver(trust_anchors=...)` turns DO on by itself (RFC 4035 §4.1¶1 — records never asked for are records never checked), and the CLI gains `--validate`, `--trust-anchor FILE` (RFC 9718 XML whose fully-expired contents end the run rather than silently validating nothing) and `--validated-cuts`. Stamp-at-write and filter-at-cut, never re-verify at cut: RFC 4035 §4.5 caches a response as one atomic entry for one TTL, and letting a DNSKEY's expiry decide a policy question from a walk whose purpose is *not* to query was refused on purpose. `test_dnssec_wiring.py` (12) scripts the three-zone descent end to end — secure denial stamped and cut with zero queries, forged proof re-walked instead of cut, both insecure-delegation shapes including the live §5.2¶6 DS query, deaf servers, the hint toward an unvisited zone that must not ask the wrong server — with fetch-hint, cache-flag, and CLI follow-on tests in the files they touch (+19) (`tests/test_dnssec_wiring.py`, `tests/test_dnssec_validate.py`, `tests/test_nsec_cache.py`, `tests/test_cli.py`).

- The four states of RFC 4035 §4.3 as a layer (`namespy/validate.py`) — the shift from "does
  this signature hold" to "may this answer be believed". `DnssecStore` buckets records from
  any number of responses into RRsets that remember the zone they arrived in (RFC 4035
  §5.3.2¶18: parent and child can each hold an NSEC at the same delegated name, the two
  "MUST NOT be combined", and a merged bucket matches neither signature — every signed
  delegation a self-inflicted bogus without this), `Validator.authenticate_zone` climbs
  from any zone to a trust point — a DS- *or* DNSKEY-shaped anchor (RFC 4033 §2 allows
  either, and `authenticate_dnskey_rrset` gained `trusted_dnskeys` to consume RFC 9718
  §2.2¶12's optional PublicKey element), an authenticated parent's DS, or the parent's
  signed proof that no DS exists — and `validate_rrset` / `validate_denial` decide answers,
  wildcard-expanded answers (RFC 4035 §5.3.4¶1's closer-match proof, demanded and
  verified), and Name Error / No Data denials under keys the chain has already vouched
  for. The states refuse to launder into one another: an unsigned child nobody proved
  unsigned is Indeterminate, not Insecure (the distinction RFC 8020 §2¶3's cut rule hangs
  on); a *missing* signature is Bogus, because RFC 4033 §5 lists it there literally and
  §4.3¶5's "not able to obtain" means absent records, not unsigned present ones; a forged
  no-DS proof makes the child Bogus rather than Insecure (strip-a-DS-sign-the-lie is the
  attack "signed proof" exists to close); a missing backend is Indeterminate top to
  bottom; an expired window is Bogus, being a check that ran and refused. A directly
  anchored island stays SECURE below a broken parent (RFC 4035 §5.1, §5.2¶7 — the parent's
  verdict is a result, never a veto), and every proof record in a bundle is verified, not
  just the one the geometry consulted ("all the signatures in the response", RFC 4033 §5).
  The tests build a three-level RSA-signed tree — real keys, real signing bytes, both NSEC
  and NSEC3 legs — and break it one octet at a time; the captured live root also validates
  end to end as an answer through the new layer (`test_dnssec_validate.py`, 45 tests).
  Nothing in the resolver consumed it at the time; the bullet above is the wiring that
  changed that, and `NxdomainPolicy.VALIDATED`'s door now refuses only the missing
  trust anchors.

- Trust anchors and the first live chain (`namespy/anchors.py`, `verify.authenticate_dnskey_rrset`) —
  the trust point the verification stage kept deferring to. The root's anchors are read from their
  live publication rather than embedded from memory: `parse_root_anchors` enforces the RFC 9718 §2.1
  schema literally (7958 is obsolete, and its PGP/CSR forms were withdrawn precisely because they
  mixed trust models — in 9718's the transport carries content and origin, §3.2¶4, so this is TLS
  plus a schema and no invented signature check), `fetch_root_anchors` retrieves it over HTTPS at
  the operator's direction with an injectable transport, and `TrustAnchor.active` enforces the
  §2.2¶7 validity windows — the published file already carries three keys, the withdrawn 2010 KSK
  *and* the 2024 one, and an implementation that ignores the windows is broken at the next ceremony
  rather than today. `authenticate_dnskey_rrset` then walks the RFC 4035 §5.2¶2-¶5 link: a DNSKEY
  matching a trusted DS by tag, algorithm and §5.1.4 digest (RFC 4034 §5.2's zone-flag proviso
  excluding the pair, with its own reportable reason), that matched key's own signature over the
  apex RRset verified through the existing §5.3.1 procedure, and the signer's name deciding which
  zone a colliding 16-bit tag actually speaks for. The outcome is three-way again — a digest type
  that cannot be computed is §5.2¶10's "treat as unsigned", an absent backend is Indeterminate, and
  neither is ever reported as forged. The tests pin the live IANA document byte for byte and a real
  signed-root response captured with DO=1: the published digests pick out the live keys, the live
  response's key tags recompute to the published numbers, the chain lands SECURE on KSK 38696, and
  every severance — withdrawn anchor, edited key octet, flipped signature octet, matched-but-unsigned
  KSK, foreign signer — refuses for exactly its own reason (`test_dnssec_anchors.py`, 43 tests).
  Nothing consumes this from the resolver yet — that is the `NxdomainPolicy.VALIDATED` wiring.

- The RFC 4035 §5.3.1 verification procedure (`namespy/verify.py`) — `verify_rrsig(rrsig, owner,
  rdatas, dnskeys)` walks the conditions cheapest-first (RFC 9904 algorithm policy, the signtime
  window, signed-byte reconstruction, key-tag/protocol/zone-flag matching) and then tries **every**
  matching key (§5.3.1¶10) through one arithmetic dispatch (`crypto.verify_dnskey_signature`) that
  owns the layout, the DER boundary and the RSA size window, so no weak or unreadable key ever
  reaches a verification call. The answer is three-way — VALID, INVALID, UNSUPPORTED — because the
  resolver's next step differs: RFC 9904's MUST NOT algorithms (RSAMD5, DSA) are INVALID even in an
  install with no backend at all, while an absent extra, an unregistered algorithm, or a candidate
  the backend cannot build a key from are UNSUPPORTED, the state RFC 4035 §4.3¶5 names
  Indeterminate to name — "we could not check" must never launder into "it is forged". The four
  published vectors authenticate end to end (RFC 6605 §6 ×2, RFC 8080 §6 per **erratum 4935** ×2);
  RSA has no published RRSIG in any RFC, so its paths are pinned by deterministic PKCS#1 v1.5
  round-trips — including RSASHA1, which RFC 9905 deprecated for signing while RFC 9904 kept
  validation a MUST, precisely because refusing to check it would report live zones as bogus.
  A VALID verdict claims only that a key in the set you supplied signed these bytes: §5.3.1¶11-¶13
  key authenticity is the trust-anchor stage, still ahead (`test_dnssec_verify.py`, 26 tests).

- The ECDSA and EdDSA encodings (RFC 6605 §4, RFC 8080 §3–§4) — the curve point as two
  fixed-width field elements, the EdDSA key as a bare 32- or 57-octet bit string, and the
  signature as fixed-width r‖s, *not* DER: §4¶2 is a MUST with no padding licence beside it,
  unlike RSA where erratum 2811 made short signatures legitimate history. Coordinates pad
  to the curve's width rather than minimising like an RSA modulus, because the key tag sums
  these octets and only one encoding of a point is correct. The DER form the backend speaks
  is converted at the boundary by a strict hand-written parser — short-form lengths, minimal
  INTEGERs, one reading per blob — because a signature encoding with two readings is a
  signature that verifies differently for different verifiers. `pack_ec_public_key`,
  `unpack_ec_public_key`, `ecdsa_signature_from_rs`, `ecdsa_signature_from_der`,
  `ecdsa_signature_octets`, `eddsa_public_key_octets`, `eddsa_signature_octets`
  (`namespy/dnssec.py`); `RData_DNSKEY.ec_public_key()`/`.eddsa_public_key()` and their
  `require_` twins; the width tables `ECDSA_FIELD_OCTETS`, `EC_KEY_OCTETS`,
  `EDDSA_KEY_OCTETS`, `EDDSA_SIGNATURE_OCTETS` (`namespy/crypto.py`). The tests pin every
  published value the RFCs print: RFC 6605 §6's two keys (tags 55648 and 10771 with their
  DS digests) and both signatures, and RFC 8080 §6 **as corrected by verified erratum 4935**
  — whose generator script had dropped the RRSIG algorithm identifier and counted the root
  label — so the corrected Ed25519 and Ed448 signatures are pinned verifying through the
  backend, and the superseded original is pinned failing. No dependency is imported by the
  layout itself; the backend only confirms it
  (`test_dnssec_ecc.py`).

- The response-level validators (RFC 5155 §8.5-§8.9, RFC 4035 §5.4) — the shapes a signed
  response can take, each with the records it owes and the split between *absent* and
  *contradictory*. `nsec3_proves_no_data` is §8.5 **as corrected by verified erratum 3441**,
  which is what makes it branch at all: as published it demanded a matching NSEC3
  unconditionally, and an Opt-Out chain holds no record at an insecure delegation (§6¶1),
  so the amended text accepts a closest *provable* encloser proof whose next closer is
  covered by an Opt-Out span — and only that. `nsec3_proves_no_ds` (§8.6) is the same shape
  reading the DS bit, the most load-bearing denial in the protocol because it is what tells
  a validator to stop below an unsigned child; §6¶4 is why its matching branch accepts an
  Opt-Out record while §6¶3 is why a covering one asserts nothing.
  `nsec3_proves_wildcard_no_data` (§8.7) rests on the wildcard's *existence* — matched, not
  covered, which is the difference between a No Data answer and the Name Error its records
  would otherwise describe. `nsec3_proves_wildcard_answer` (§8.8) takes the synthesising
  name the caller read from the covering RRSIG's Labels field and demands the span over the
  "next closer", which is RFC 4592 §3.3.1's "no search for an alternate" made verifiable.
  `nsec3_proves_unsigned_delegation` (§8.9) validates a referral into an unsigned zone, and
  its SOA-bit check is the parent test: a record that matches the delegation name while
  listing SOA is the child's own, quoted as the parent's word. `nsec_proves_no_data`,
  `nsec_proves_nxdomain_response` and `nsec_proves_wildcard_answer` assemble the thinner RFC
  4035 §5.4 text into the same shapes, with the §5.4¶3 Labels equality for callers holding
  the covering RRSIG and the CNAME-bit check RFC 5155 §8.5¶1 spells out and RFC 4035 leaves
  to the reader. Every entry point filters through `usable_nsec3` first, every result names
  the records a proof rests on and flags whether it runs through an Opt-Out span — the AD
  prohibition of RFC 5155 §9.2¶1, pre-computed and waiting for a header that can model the
  bit — and every failure is an `IncompleteProofError` (§5.4¶6: ask again) or a
  `ContradictoryProofError` (no retry will help). Nothing here verifies a signature yet;
  the shapes are what a response owes before its RRSIGs are read at all.
  `tests/test_nsec_responses.py` (44 tests), including the two findings of writing it:
  under NSEC the wildcard of an encloser can never be *missing* — `*.encloser` sorts
  directly above the encloser, inside the encloser's own span, so both proof halves ride
  on one record — which is a geometric fact NSEC3's hashed order does not have; and the
  erratum's asserting-span refusal is a contradiction rather than an incomplete proof,
  because a record asserting QNAME's absence while the response asserts its presence is
  two claims that cannot both stand.

- Extended DNS Errors (RFC 8914) — the `ERROR` option, EDNS option code 15, is composed
  *and* consumed. `ExtendedDNSError` in `namespy.edns` holds an INFO-CODE and the
  EXTRA-TEXT that followed it and interprets neither: §2 says the text "is intended for
  human consumption (not automated parsing)", so `extra_text` keeps exactly the octets the
  option carried — a trailing NUL survives, because §2 also says text "may be null
  terminated but MUST NOT be assumed to be", and only `.text` drops one, for display —
  while `.option` writes the INFO-CODE-then-text payload §2's figure describes. Receiving
  is deliberately broad, because §3 is emphatic: "Receivers MUST be able to accept EDE
  codes and EXTRA-TEXT in all messages, including those with a NOERROR RCODE but need not
  act on them", and its next sentence lets a sender include *more than one* option. So
  `extended_errors_of` returns all of them in wire order and raises nothing — not even for
  an option too short to hold a code, which is a wire-format error on the way *in*
  (RFC 6891 §7's badly-formatted option, answered FORMERR) and merely skipped by a
  *receiver*. That asymmetry is §6: EDE "MUST NOT alter DNS protocol processing", so a
  four-octet defect must not cost the answer riding beside it.
- Explaining a failure, on the way out (RFC 8914 §2, §3, §4.22, §4.23): the demo server
  puts the reason behind a failure it caused into an `ERROR` option instead of handing
  over a bare rcode. A walk that ran out of authoritative servers answers SERVFAIL with
  22 (§4.23, "The resolver could not reach any of the authoritative name servers") and a
  non-QUERY opcode answers NOTIMP with 21 (§4.22, "The requested operation or query is not
  supported"), each with EXTRA-TEXT short enough to obey §3's "SHOULD avoid lengthy
  EXTRA-TEXT contents" and naming this software rather than anything §2's
  private-information caution warns against. Four limits are deliberate: the option goes
  only to a requestor that sent an OPT (§7), it is never echoed out of a query (§6.1.1
  forbids forwarding what arrived), it never decorates a rejection that already explains
  itself (BADVERS and FORMERR carry their own reason), and it is the first thing dropped
  when the reply would overflow what the client advertised — §3 prescribes that order:
  "servers SHOULD truncate messages by dropping EDE options before dropping other data".
- Consuming one, on the way in (§3, §6): a received code is diagnosis and nothing else.
  It joins the reason a dead zone is remembered for — three codes at most, because §3
  leaves the count to the sender and a reason quoting twenty has stopped being a reason —
  and it reaches the debug log, where RFC 5358 §4.2's reasoning and §6's "unauthenticated
  information" agree that somebody else's octets are logged at DEBUG and nowhere louder.
  Nothing branches on an INFO-CODE. The CLI prints each one on its own `; EDE:` line
  beside the EDNS one, on *any* rcode rather than only under a failure (§3's codes 3 and 4
  travel with answers a resolver may legitimately use), with control characters escaped
  and the text capped on screen — §6's MITM sentence describes a text field that this
  program is about to hand to a terminal. What it does *not* do is forward an upstream
  code to this resolver's own client: §3 calls that "implementation dependent", and the
  failure path returns `None` rather than a message, so propagation would mean
  synthesising a response nothing here builds. `tests/test_edns_error.py` (21 tests),
  plus the EDE sections of `test_server.py`, `test_failure_cache_resolver.py` and
  `test_cli.py`, pin all of it.
- Resolution failures are cached now (RFC 9520 §3.2, §3.3) — `FailureCache` and
  `FailureEntry` in `namespy.cache`, consulted by `resolve_steps` before it sends
  anything and owned by `RecursiveResolver` (`failure_cache=`: pass a cache to share
  one between resolvers, leave it out for a default one, pass `False` to switch it
  off — `False` rather than `None` because `None` means "give me the default"
  everywhere else in that constructor, and a resolver built to *watch* a zone fail
  has to keep asking it). A lookup that dies because a zone's servers never answered
  records the **zone**, not the name that happened to ask, because the next query
  will be for a different name under that zone: §3.3 asks that a non-responsive
  zone's parent be limited "just as it would limit subsequent queries to the
  non-responsive zone", and only a zone key can express that. A suppressed lookup
  ends without a `Response` — which the server already answers SERVFAIL — with no
  packet leaving the process. Failures that are properties of a name are keyed on
  `(QNAME, QTYPE, QCLASS)` instead: an alias loop (§2.5), a spent hop budget, or a
  lookup that had no server to ask at all. Two exclusions keep the cache from
  inventing outages — a zone this lookup never queried, and one that answered
  something usable along the way, which is what a finished QNAME-minimisation probe
  walk looks like. Entries live between one second and five minutes (§3.2's band;
  the floor is configurable, the ceiling is a MUST so it is not), double per repeat
  failure, and are LRU-bounded so the memory §3.2's resource-exhaustion concern
  fears is fixed by configuration rather than by how many garbage names someone can
  invent. Suppression does not extend an entry, or a client hammering a dead name
  would hold a recovered zone shut at the ceiling; a lookup that *succeeds* clears
  what was remembered about that name and about every zone that spoke during it,
  which is how recovery gets noticed rather than waited for. What is *not* cached is
  an unresponsive server address, which §3.2 permits: inside one lookup the Slist
  already cycles a zone's remaining servers, and across lookups an address key would
  retire one of a zone's several healthy servers for minutes over a single dropped
  datagram. `--no-failure-cache` is the way out from the command line.
- EDNS(0) *options* — the code/length/value records that live inside OPT RDATA
  (RFC 6891 §6.1.2), which until now was written empty and read as an opaque
  blob. `namespy.edns` carries them; a query can now hold NSID (RFC 5001),
  COOKIE (RFC 7873) and Padding (RFC 7830), and `--nsid` asks every server the
  walk touches to say who it is. What comes back is printed as hex, because
  §2.4 of RFC 5001 asks for two digits per octet — an identifier is meant to be
  pasted into a report, not recognised on sight — and a query that was asked to
  identify servers but was met with silence says so, since RFC 6891 §6.1.2
  requires that an option code a responder does not understand be ignored, and a
  server that never implemented the option is exactly that responder. A
  server answers NSID only when the question was actually put to it
  (§2.2), ignores an identifier a requestor tries to hand it (also §2.2), and
  `--advertise-nsid` is what gives the demo server one to answer with. Each
  responder's advertised payload size is now remembered and applied as the
  ceiling on the next query sent to *that* server (RFC 6891 §6.2.3, §6.2.4):
  the number is what governs how big a reply it may send without fragmenting
  the datagram, so offering it more than it asked for bought nothing but a
  possible fragment. Padding round-trips and names the block it pads, but is
  never applied to a query on plain UDP — RFC 7830 §6 forbids it there, and
  there is no encrypted transport in this codebase to apply it over. A
  misformed option in a *query* is answered FORMERR, and that answer carries an
  OPT: §7 requires it, because "the response MUST include an OPT record" when the
  failure was in the OPT itself — "to allow the requestor to distinguish between
  servers that do not implement EDNS and format errors within EDNS". A server
  that does implement EDNS and found the request malformed must not look like one
  that does not. A cookie option of 9 octets is refused the same way, and so is
  one of 41: RFC 7873 §5.2.2 says "valid cookie lengths are 8 and 16 to 40
  inclusive", so 9 through 15 cannot be a client cookie plus a server cookie of
  any legal size — accepting
  one would be validating a nonce the requestor cannot reproduce. An option code
  this code does not model is ignored instead (§6.1.2), because an experimental
  code is somebody's deployment choice rather than a defect. A misformed one is
  not forgiven in either direction: a declared length that runs past the end of
  the RDATA raises instead of being quietly truncated, which is what lets the
  server turn it into the FORMERR above.
  Pinned by `tests/test_edns.py`, the EDNS section of `tests/test_server.py`,
  and the NSID tests in `tests/test_cli.py`.
- The demo server is now an EDNS(0) responder (RFC 6891 §6.1.1, §6.1.3, §6.2.4,
  §7). A query that carried an OPT gets one back carrying *this* server's
  payload size — never the one the recursive walk collected, since §6.1.1
  forbids forwarding OPT and its CLASS and FLAGS describe somebody else's
  stack; a query that carried none gets none, which is what §7 requires of a
  responder talking to a requestor that announced no EDNS at all. A query with
  two OPT records is answered FORMERR before the resolver is touched, and a
  VERSION this server does not implement is answered BADVERS with `version=0`
  in the OPT — the number that tells the requestor how far down to go. Pinned
  by the EDNS section of `tests/test_server.py`.
- Serialising an effective RCODE above 15 now puts the upper eight bits in the
  OPT record that carries them. A `Response` built in memory holds the whole
  code in `RCODE`, and the wire writer shifted it by 4 — the shift in the
  *effective*-RCODE formula, a different quantity — so it landed in VERSION
  instead of EXTENDED-RCODE and `RCODE=23` (EXPIRED) reached the wire as 7
  (FORMERR). `test_an_extended_rcode_is_stamped_into_the_opt_that_carries_it`
  pins it; the hand-stamped wire-in direction was already pinned by
  `test_badvers_round_trips`.

- QNAME minimisation (RFC 9156), opt-in: `RecursiveResolver(qname_min=True)`
  or `namespy --qname-min`. Servers not known to be authoritative for the
  full name receive progressively deeper children — the section 2.3 probe
  schedule is pinned by `test_minimis.py`, the descent integration by
  `test_qname_min.py`. Terminal *probe* responses demote and continue
  (section 3 step 4) instead of answering for the original QNAME; budget
  exhaustion degrades to full-name queries; `--trace` marks probes. Off by
  default because it changes wire behaviour toward every downline server;
  CNAME chasing deliberately keeps full names.
- Out-of-bailiwick glue is now a *policy* rather than only a behavior, so the
  exposure it prevents can be measured. `GluePolicy` (`STRICT` default,
  `PERMISSIVE`) is accepted by `RecursiveResolver`, `resolve_steps` and
  `classify`; `namespy --allow-out-of-bailiwick-glue` reaches it from the CLI and
  prints a warning on stderr, since an answer obtained this way may have been
  steered by whoever delegated. Either way a referral's volunteered address is now
  a `VolunteeredGlue` trace event — previously the address was discarded inside
  `classify` and left no mark, so the interesting population (who volunteers glue
  for someone else's nameservers, and what would happen if it were believed) was
  exactly the part that could not be observed. `--trace` renders each one as
  believed or discarded, and the policy is inherited by the glueless
  sub-resolution so it cannot loosen halfway down a descent. Pinned by
  `test_glue_policy.py`, with the end-to-end difference in destination shown by
  `test_resolver_e2e.py`.
- `RecursiveResolver.aclose()`, plus `async with` support, releases every socket
  a resolver owns: the endpoint transport asyncio attached, the private IPv6
  socket it opens for AAAA glue, and a bring-up task still in flight. Fails are
  completed with `RuntimeError` rather than cancelled, so a caller's
  `asyncio.wait_for` reports that *this* resolver closed instead of appearing to
  have been cancelled from outside. Both CLI modes use it, and the library
  example in the README now shows it next to `transport.close()`. Pinned by
  `test_resolver_lifecycle.py`.
- Security CI (`.github/workflows/security.yml`): CodeQL with `security-extended`
  (weekly and on change), `dependency-review` on every pull request, and
  `pip-audit` over the resolved dev environment. `socket.yml` screens every
  dependency install through the Socket.dev firewall. `master` is protected:
  all checks must pass, strictly, before anything lands.
- Release path completed (`.github/workflows/release.yml`): SLSA build
  provenance via `actions/attest`, PyPI attestations via trusted publishing,
  a `pypi` deployment environment scoping who can mint an upload credential,
  a GitHub Release created only after PyPI accepted the artifacts, and a
  `workflow_dispatch` rehearsal path that no longer trips its own tag check.
- `tests/test_review_fixes.py` — locks every finding from the correctness
  review (TTL clamp, trailing-RDATA refusal, empty-label refusal, cancellation
  pending-slot release, log-level discipline, server spawn bound).
- SVCB and HTTPS (RFC 9460) — types 64 and 65 stop being an RFC 3597 hex blob.
  `RData_SVCB`/`RData_HTTPS` in `namespy.rdata` carry the priority, the TargetName
  and a `SvcParams` object; `namespy.svcb` is the module behind them. Encoding
  obeys §2.2's "SvcParamKeys SHALL appear in increasing numeric order" — the
  parameters are stored by key number and written in sorted order, so a record
  built in the wrong order still leaves this program canonical, while *receiving*
  out-of-order or duplicated parameters is refused as a wire error rather than
  quietly normalised. Unknown keys are kept, not dropped: §2.1.1 does not make an
  unrecognised SvcParam a wire error at all — it matters only when it is
  mandatory, and then the whole record is ignored — so nothing here edits one
  away, and `keyNNNNN` (§2.1) round-trips so a generated zone file says what it
  meant.
  `select_records()` implements the §2.4 client behaviour — AliasMode wins over
  every ServiceMode record in the RRset, records that fail a test cost only
  themselves unless `strict=True` takes §2.4.3's option of rejecting the RRset,
  and each discarded record arrives in `skipped` with the reasons that removed it.
  §8's automatically mandatory keys are the part most likely to be got wrong: an
  `HTTPS` mapping mandates `port` and `no-default-alpn` without saying so in the
  RDATA, so `SvcbCandidate` carries them separately from any explicit `mandatory`
  parameter and a client that supports neither is told, correctly, to ignore the
  record. RFC 9460 Appendix D is the test oracle: `tests/test_svcb_rdata.py` (30
  tests) walks every figure through both wire decoding and presentation parsing.
  `tests/test_svcb_wire.py` (46) works the framing one level below that — a partial
  parameter header, a `SvcParamValue` length that overruns the RDATA, keys out of
  order, an uninterpretable key followed by a readable one — and holds every
  registered key's value to its own section, which is where §2.2's third malformed
  condition bites: a key that was not recognised as registered would let a corrupt
  `port` through as a record that merely has no `port`, silently changing how the
  client connects instead of losing the record. `tests/test_svcb_presentation.py`
  (101) covers §2.1's encoding rules in both directions — charstring escaping,
  value-list splitting and joining, the `keyNNNNN` spelling, and the rejections.
- MQTYPE (RFC 10029) — asking several QTYPEs in one exchange without touching the
  Question section, so QDCOUNT stays one and RFC 9619's "QDCOUNT Is (Usually) One"
  argument survives untouched; the extra types ride in EDNS options 20 and 21 (§5).
  `namespy.mqtype` builds and reads both, and the asymmetry between them is the
  design rather than an accident: §3.3 makes an inbound MQTYPE-Response a FORMERR on
  its own, and §3.5 makes the *absence* of a MQTYPE-Response the way a server says it
  does not support the extension, so the two directions could not share one code with
  a flag inside it. Hence two constructors instead of one taking a flag, because only
  one of the two lists may be empty: §3.3 requires FORMERR for "an MQTYPE-Query option
  with an empty QT list" while §3.4 says the opposite of the answer — "it is possible
  for the resulting MQTYPE-Response option to contain an empty list, but as described
  above, the option must still be returned". Presence is the support signal and
  contents is what was combined, and Appendix A.3's DS-plus-NS figure is precisely
  that empty case. `mqtype_query_rejection()` holds all eight §3.3 conditions and the
  constructors refuse the same list on the sending side, because §3.2 obliges a client
  to "generate packets that conform to the server request parsing rules described in
  Section 3.3" — one shared validator, so the two ends can never drift apart about what
  is valid. Validity turns on RFC 6895 §3.1's data/QTYPE/Meta partition, which is why
  `enums.rrtype_class()` exists: a range check cannot do it, because `OPT` (41) is a
  Meta-RR numbered inside the data band while 128–255 is a gap the policy never
  allocated to data, and an unassigned number above the gap (300) is a perfectly good
  QTx — refusing it would be RFC 3597 §3's error. Reading an answer is three outcomes
  rather than two, because §3.5 commands three different things: absent means
  "unsupported", so keep the primary answer and re-ask the rest; present means use it;
  present-but-self-contradictory (the option twice, or a QTx repeated, or one
  repeating the primary QTYPE) means "treat the answer as invalid (equivalent to
  FORMERR)". Collapsing the third into the first is the dangerous mistake, since it
  keeps using an answer the client was told to discard — so
  `mqtype_supported()` and `mqtype_answered_qtypes()` are separate, the first never
  raising and the second raising for exactly those contradictions.
  `qtypes_still_needed()` is the work list §3.5 demands and pointedly not a negative
  answer: a missing QTx has four innocent reasons (nothing cached, flags or rcode
  mismatched, unwilling server, response too big), none of which is NXDOMAIN or NODATA.
  §4's "a limit of four QTx values would be appropriate" is offered as
  `MQTYPE_RECOMMENDED_QTX_LIMIT`, which is what both the server's `max_qtypes` and the
  demo server's `--max-qtypes` default to — one constant, so an undecided library and an
  undecided command line cannot disagree about what they got. The knob is a real dial
  because §4's paragraph is a policy rather than a cap: `None` leaves only the ceiling an
  EDNS option has in any case — §3.1 gives OPTION-LENGTH no count field of its own, so
  the list is bounded by RFC 6891's 16-bit option length, which `EdnsOption` already
  enforces, and by the UDP payload the query advertises, which runs out far sooner —
  and zero answers the option while buying none of the lookups, which is
  a refusal of *this much work* and sounds nothing like the silence that means the
  extension is absent. The demo server enforces §3.3 (malformed → FORMERR, with
  an OPT per RFC 6891 §7) and, given a well-formed query, combines: each QTx is resolved
  through the same semaphore slot as the primary lookup, so one client stays one
  exchange however many types it asked for (§4's amplification argument), and the answer
  grows by whatever the primary response does not already hold. §3.4's rules are each a
  separate guard. A record already present is not added twice, where "present" is RFC
  2181 §5's identity — name, type, class, RDATA, TTL excluded — which is why an SOA that
  appears in both the Answer (NODATA) and the Authority (proof of absence) sections
  stays two records. A QTx whose answer disagrees with the primary on rcode, `aa`, `tc`
  or `ad` is left out, because those are one bit per message and the option may not name
  a type whose records are absent. A response that would grow past what the client
  advertised stops combining instead of setting `TC`, since a listed QTx is promised in
  full and §3.5's recovery from a missing one is to re-ask, not to be told the answer was
  cut. A `TC` primary stops the loop on its own — the full set can only arrive over TCP,
  and the option belongs with the answer that reaches it — and every one of those stops
  still returns the option, empty if nothing was folded in, because §3.4 makes presence
  the support signal and §3.5 makes absence the signal to retry type by type. Where RFC
  8914 §3's "drop EDE options first" would have taken the reply's explanation with it,
  the explanation is what goes and the MQTYPE-Response stays. `tests/test_mqtype.py`
  (44) uses Appendix A's three figures as the oracle and covers every §3.3 condition and
  each §3.5 outcome; sixteen in `tests/test_server.py` hold the server to both halves of
  its posture — the refusals and the combination rules down to the octet, and the exact
  reach of the operator's limit, zero and unbounded included; and 22 in
  `tests/test_enums.py` pin every boundary of the §3.1 allocation table.
- MQTYPE on the asking side (RFC 10029 §3.2, §3.5) — `namespy.bundle` reads a combined
  answer, `RecursiveResolver.resolve_bundle(packet, (AAAA, HTTPS))` walks once, and
  `--mqtype TYPE` (repeatable) puts it on the command line. The reader is a module of its own
  because the failure this feature invites is a cached lie, and it is a failure about
  *absence*: §3.5 gives four reasons a requested QTx can be missing from the MQTYPE-Response —
  nothing in cache, flags that did not match, a server unwilling to do the work, a size limit
  — and not one of them is "this name has no records of that type". So an unlisted type comes
  back as `BundleState.NEEDED`, a work list rather than a verdict, and only the types the
  answer vouched for reach the cache. §3.5's "The client MUST subsequently initiate separate
  standalone queries for all QTx values for which an answer is still required" is what
  `resolve_bundle` does by default; `ask_separately=False` hands that decision to a caller who
  knows whether it wants an AAAA at all. `supported` and `void` are two fields instead of one
  boolean because the two cases want opposite things: a server that never implemented the
  extension answers the primary question perfectly well, and §3.5 says to process it "as if the
  MQTYPE-Query option had not been used", while a server that duplicated a QTx or sent the
  option twice has produced an answer §3.5 makes equivalent to FORMERR — which voids the
  harvest *and* the primary, so the void is caught in `resolve_steps` before classification,
  since anywhere later the bad answer has already been cached on its way to being rejected.
  §3.5's ranking rule (RFC 2181 §5.4.1) cuts both ways: an authoritative NODATA for a listed
  QTx is a negative and caches like any other under RFC 2308 §5, and one that nobody vouched
  for caches as nothing at all. Each entry also carries where its answer came from —
  `BundledType.separate` — because a combined type and a re-asked one are otherwise the same
  state with records attached, and only the first was combined by anybody.
- The list travels with the walk, not with one query. An MQTYPE-Query option rides every send
  of the descent it belongs to and none of the lookups that merely support it: a QNAME
  minimisation probe asks the child so that a server can answer NOERROR rather than name the
  zone, while §3.4 evaluates each (QNAME, QCLASS, QTx) combination against the flags of *the
  query that asked* — so a probe carrying the list invites a server to attribute the parent's
  RRsets to the child's name. Glue sub-resolution is excluded for the same reason: it asks
  about a nameserver's name at somebody else's request, and its answer is not this bundle's.
  §3.3's refusals are refused before they are sent — a repeated QTx, one that is a Meta-RR
  rather than a data type, a bundle behind a non-data primary such as ANY, which §3.3 makes a
  FORMERR rather than a difference of opinion — and a server that rejects the option is
  stepped down
  the way RFC 6891 §6.2.2 steps anything else down: drop the option if a reply comes back
  FORMERR carrying an OPT, drop EDNS entirely if it comes back FORMERR without one.
  `tests/test_bundle.py` (28), `tests/test_resolver_mqtype.py` (28) and twelve in
  `tests/test_cli.py` hold the reader, the threading, the three fallbacks and the rendering;
  `bundle.py` is at 100% coverage. And because each of those suites only ever talked to a
  response this project wrote by hand, `tests/test_mqtype_interop.py` (4) wires the real
  client to the real responder over a real datagram — the client encodes, the server parses,
  combines, and answers, and the client's harvester reads the result — for the combined,
  declined, and partly-completed cases. It found the malformed fixtures below on the first run.
- A bundled hop is now visible in `--trace`. `SendQuery` has carried `extra_qtypes` since the
  option shipped, but `to_mermaid()` only ever marked probes, so `last_resolution.md` showed a
  line-for-line identical diagram whether a descent had bundled three types into one query or
  fetched each with its own — and it still would, because the fallback answers every type
  either way and only the trace can tell. Each bundling hop now reads `example.com. A
  (mqtype +2)`, counted rather than named because this module dispatches on class names
  precisely so it never has to import the resolver. The standalone re-asks, which had been
  invisible — each built a trace that `resolve_bundle` then discarded when it restored the
  bundling descent — are attached as child traces and render as their own diagrams, so the
  file says what was asked and how many times. A lookup that did not bundle renders exactly as
  before, marker absent, which is what the existing mermaid tests pin.
- The NXDOMAIN cut (RFC 8020 §2) — a NXDOMAIN already in the cache now denies the names at and
  below it, so a lookup that RFC 2308 would send upstream is answered from the denial the zone
  already made. §2¶1's claim is about *names* — "all names and resource record sets (RRsets) at
  or below that node SHOULD be considered unreachable" — while a negative entry is keyed
  `(name, qtype, class)`, so the
  NXDOMAIN that arrived in answer to an A was invisible to the AAAA this cut is meant to serve.
  That is why the change is in the cache layer and not the resolver: `DnsCache.nxdomain_at(name,
  qclass)` is the QTYPE-free lookup `get()` cannot be. Its SQLite form is one read on the primary
  key's leftmost column; its in-memory form is an index maintained on every removal path, because
  the cut is consulted on every hop of every query and a scan of the cache per hop would cost
  more than the traffic the cut saves. The base implementation returns `None` rather than raising:
  the cut is a SHOULD, so a backend that cannot answer it keeps walking, which is the behaviour
  from before it existed. Two consequences of §2 that tests caught by failing — and were right to:
  the *name itself* is cut for every other type, since §2¶1 says "at or below that node" and the
  node is the denied name — re-proving a nonexistence the zone already stated is not what RFC 8020
  asks for; and the cut
  must be consulted at *every* hop, because §2¶6 makes the denied name the last one in an alias
  chain, so a resolver that checked only at the origin would walk straight into a subtree its own
  cache says is unreachable. `NxdomainPolicy` decides all this and sits beside `GluePolicy`
  deliberately: `ALWAYS` is the §2 SHOULD, and `NEVER` exists for the reason §2¶4 gives — "The
  fact that a subtree does not exist is not forever" — so a name created under a denied node is
  invisible until the negative entry expires, which is wrong for serving and exactly right for
  watching a zone change, the same split `--no-failure-cache` draws. Unlike permissive glue it
  gives up an efficiency rather than a defense, so it logs instead of warning on stderr.
  `VALIDATED` is §2¶3's MAY — cut only when the NXDOMAIN was DNSSEC-validated — and is refused at
  the door with a message naming DNSSEC, because it and `NEVER` emit identical packets while
  nothing here validates, and a silent fallback would let an operator believe proofs were what
  stopped the cut; the test that pins the refusal is the one that has to change when validation
  arrives. A cut's answer is indistinguishable on the wire from a denial fetched for the name
  asked about — the reply carries the *ancestor's* SOA beside a question naming the deeper name —
  so `--trace` gains `NXDOMAIN cut: www.foo.example below foo.example` and the answer a matching
  `;;` line, both naming the ancestor, and both halves reported in the case the query used because
  a line whose two names differ only in case reads like two names. A cached denial is consulted
  before the RFC 9520 failure note where the two overlap, since one is a proof with an SOA behind
  it and the other only a promise not to ask again.
- The first leg of DNSSEC (RFC 4034 §2, §5, Appendix B) — `DNSKEY` and `DS` stop being RFC 3597
  hex blobs. `namespy/dnssec.py` holds the arithmetic and `RData_DNSKEY` / `RData_DS` in
  `namespy/rdata.py` are the codecs, registered on type numbers 48 and 43 like every other
  type this package understands. The point of doing these two first is that they need no
  dependency: a DNSKEY carries a public key it never interprets (§2.1.4 defers the format to
  documents this package does not implement), a DS carries a hash it never checks, the key tag
  is a 16-bit checksum, and the digest is one `hashlib` call over "DNSKEY owner name | DNSKEY
  RDATA" (§5.1.4). Signature verification — RSA, ECDSA, EdDSA — is where the dependency
  decision actually lives, and it is still ahead.
- Both published vectors in RFC 4034 are the tests, so nothing here is a number this code
  computed and then agreed with: §5.4's DNSKEY yields key tag **60485** and SHA-1 digest
  **2BB183AF5F22588179A53B0A98631FAD1A292118** exactly as printed. A checksum with no other
  vector is cross-checked against a second, independent transcription of Appendix B's reference
  C code over odd and even lengths.
- Two verified errata change the answer and are pinned by name. **4552** corrects Appendix B's
  prose ("ignoring any carry bits") to what the C actually does — accumulate at 32-bit
  precision, fold once, discard only the carry that fold produces — and warns the result is
  "often the same as reduction modulo 65535, but not always"; `test_key_tag_is_not_reduction_modulo_65535`
  uses the smallest input where they differ, because a shortcut that agrees on
  most keys and disagrees on some lands its disagreement on a delegation. **193** corrects
  §B.1's parenthetical for algorithm 1 from "4th to last and 3rd to last" octets to "3rd to last
  and 2nd to last", which is what its own normative phrase always meant; the vector there is
  built so the two readings give different numbers.
- Digest types are the ones this package can actually produce — SHA-1 (§A.2), SHA-256
  (RFC 4509 §2), SHA-384 (RFC 6605 §2) — and minting any other refuses *by number* rather than
  approximating it. Reading is deliberately more forgiving than writing: a DS with an unknown
  digest type parses, round-trips and prints, because refusing to parse a delegation would turn
  this resolver's ignorance into SERVFAIL for someone else's zone. Same asymmetry in `DNSKEY`:
  a key with the wrong Protocol or a missing Zone Flag is kept and reported
  (`may_verify_rrsets`), not dropped at parse time, because §2.1.2 puts that judgement at
  verification and an operator needs to see which rule the zone broke.
- The second leg of DNSSEC (RFC 4034 §3–§4, RFC 5155) — the proof records decode.
  `RData_RRSIG`, `RData_NSEC`, `RData_NSEC3` and `RData_NSEC3PARAM` in `namespy/rdata.py`,
  on shared ground in `namespy/dnssec.py`: `encode_type_bitmap`/`decode_type_bitmap`
  (§4.1.2's window blocks, whose ordering and trailing-zero MUSTs leave exactly one legal
  encoding per set of types, so equality on rebuilt bytes is sound), `nsec3_hash` (§5's
  `IH(salt, x, k)` recursion), `encode_base32hex`/`decode_base32hex`, and
  `iterations_within_limit` (§10.3's ceiling table). Still no new dependency: the NSEC3 hash
  is `hashlib.sha1`, the algorithm §11 registers, and the bitmap is arithmetic.
  **Verified erratum 3544** is why the base32 helper is not `base64.b32encode`. RFC 5155 §3.3
  prints "base32" where RFC 4648 §7 base32hex is meant — the two alphabets share no character
  below `K`, so a hash written the other way produces a label that exists in no zone, and the
  failure would read as a zone with no NSEC3 chain rather than as an encoding bug. All twelve
  of Appendix A's hashes reproduce exactly (`test_nsec3_hash_reproduces_the_published_vectors`),
  which pins the recursion at the same time — §3.1.3's *iterations* counts additional hashes,
  so `iterations: 12` is thirteen invocations, one short of what a careless reading gives —
  plus §6.2 item 4's rule that a wildcard hashes with its `*` label intact
  (`*.w.example.` has its own entry) and the entry whose first label is itself a hash.
  `RData_RRSIG` computes nothing but does enforce §3.1.5: `within_validity` compares the two
  time fields with RFC 1982 serial arithmetic, reusing what `RData_SOA.serial_ahead` already
  had for SOA serials, because §3.1.5¶2 states that an Expiration numerically *below* its
  Inception is legal and "all comparisons involving these fields MUST use Serial number
  arithmetic" — `test_rrsig_validity_survives_the_32_bit_wrap` holds that, since a plain
  integer comparison would quietly reject live signatures for half of 2105–2106.
  Reading stays forgiving and writing stays strict, as with `DNSKEY`/`DS`: an NSEC3 with hash
  algorithm 2 parses, round-trips and prints, but `hash_owner()` refuses rather than inventing
  a hash function, and a Hash Length of 7 for SHA-1 is rejected on receipt even though §3.1.6's
  field permits it, because a truncated hash is a proof that proves nothing.
  **The repo's own sweep caught a live bug**: `test_rdata_wrapping.py` demands a payload per
  registered codec, and writing one exposed an RRSIG header format spelled `!HBBIIHI` where
  `!HBBIIIH` is right — same 18 octets, and it read the Key Tag into the Inception Time. The
  field-order test now says so in its docstring.
- The cryptographic dependency decision, taken and bounded rather than deferred: a
  `crypto` extra in `pyproject.toml` pointing at `cryptography>=50.0.2`, and
  `namespy/crypto.py` as the one module allowed to find it. Named for the capability and
  not for DNSSEC on purpose — a feature-named extra has to be renamed the first time
  anything else needs arithmetic, and renaming a published extra breaks everyone who
  installed it. `import namespy` still imports no third-party module at all, which a test
  now proves in a fresh interpreter rather than asserting about.
  What the probe carries is the *policy*, not the arithmetic. `IMPLEMENT_FOR_VALIDATION` is
  RFC 9904 Table 2's "Implement for DNSSEC Validation" column — including the pair that
  surprises, RSASHA1 (5) and RSASHA1-NSEC3-SHA1 (7), which RFC 9905 deprecated for *signing*
  while Table 2 keeps them MUST for *validation*, because a resolver that refuses them cannot
  read the zones still signed with them. `SIGNATURE_ALGORITHMS` pairs each number with its
  primitive and digest per RFC 3110 / RFC 5702 / RFC 6605 / RFC 8080, and a test asserts the
  two tables agree: every MUST number has a primitive, and no MUST NOT number sneaks in.
  `require_backend("verify an RRSIG")` refuses with the exact extra to install, because
  "no crypto" is a line an operator reads in a log; `MissingCryptoError` is a `RuntimeError`
  and not an `ImportError` so the resolver can treat it as a policy refusal — answer
  unauthenticated and say why — rather than a broken install.
  `MAX_RSA_KEY_BITS` is 4096 (RFC 3110 §2) and marked as not-yet-enforced on purpose: the
  backend documents "denial of service via parsing untrusted key material" as outside what it
  treats as a security issue, which is a reasonable line for a general-purpose library and
  precisely the reason a resolver reading DNSKEYs off the wire needs its own. The marker test
  moves when the enforcement lands, the way `NxdomainPolicy.VALIDATED` marks validation.
  **Why this library, in short:** it is the only candidate that covers the whole MUST set in
  one dependency, is governed by the Python Cryptographic Authority with a published security
  policy (48-hour acknowledgement; security support for "the main branch as well as the most
  recent release"), ships abi3 wheels for Windows/macOS/manylinux/musllinux across five
  architectures with build provenance attested on every file, and documents the three
  integration points DNSSEC needs — `decode_dss_signature` for the fixed-width r‖s that RFC
  6605 §4 uses instead of DER, `from_encoded_point` for the tag-stripped point a DNSKEY
  carries, and raw-byte Ed25519/Ed448 loading per RFC 8080. All three are now exercised by a
  test in the new CI job, including that an off-curve point is refused rather than trusted.
  `python-ecdsa` was rejected on its own instruction ("should not be used in production
  settings") and for having no RSA at all — which leaves it unable to do 5, 7, 8 or 10;
  `pycryptodome` is capable and self-contained but is a single-maintainer project without the
  provenance posture; `PyNaCl` has no RSA and no NIST P-256, so it cannot cover the MUST set
  either. Implementing verification in pure Python was considered for the RSA numbers and
  rejected: the hazard there is not the modular arithmetic but the PKCS#1 v1.5
  `DigestInfo` parsing, which is where the historical forgery bugs live.
- The canonical RRset — the exact octets a DNSSEC signature covers (RFC 4034 §6.2, §6.3,
  §3.1.3, §3.1.8.1; RFC 3597 §7). `canonical_rdata_octets`, `canonical_rr_bytes`,
  `canonical_rrset_bytes`, `canonical_rrset_rdatas`, `rrsig_signed_data`, `signed_owner_name` and
  `rrsig_label_count` in `namespy/dnssec.py`, with `canonical_wire()` on `RData` and on every
  codec that carries a domain name and `signed_data_prefix()` on `RData_RRSIG`. This is the last
  piece of DNSSEC that needs no dependency and no trust anchor: it produces the byte string a
  signature is checked against and verifies nothing itself.
  §3.1.8.1¶5 is the sentence most likely to be read carelessly — `RR(i) = owner | type | class |
  TTL | RDATA length | RDATA` repeats the owner, type and class **inside every record**, rather
  than stating them once for the set — so the test counts the ten-octet difference between a
  one-record and a two-record set instead of trusting that the shapes look right.
  **Which types downcase the names inside their RDATA turned out to be a two-document question,
  and my earlier note about it was wrong.** RFC 4034 §6.2 item 3 and RFC 3597 §7¶4 each carry a
  verified erratum for omitting entries the other has — **1062** against 4034, **1063** against
  3597 — and the union is what implementations settle on: §7¶4's pre-2003 types plus RRSIG and
  NSEC, which RFC 4034 adds by name. RFC 3597 §7 is therefore not "the full set", and NSEC3 has no
  embedded domain name to downcase in the first place (its hashed owner name is opaque octets).
  More consequentially, §7¶5 says that for any type defined *after* RFC 3597 "the canonical form is
  such that no downcasing of embedded domain names takes place" — so HTTPS and SVCB keep the case
  of their target-name even though it is a domain name (RFC 9460 says nothing about canonical
  form, so §7¶5 governs), and `test_a_type_after_rfc_3597_keeps_the_case_of_its_embedded_name`
  pins that against the "downcase anything with a name in it" instinct. The list is built from the
  type registry rather than typed-out numbers, and asserted as mnemonics, so it reads against the
  RFC's sentence and cannot gain a digit quietly.
  Two rules that look cosmetic are not. §6.3¶1 orders RDATA as "a left-justified unsigned octet
  sequence in which the absence of an octet sorts before a zero octet", which is plain bytes
  comparison — what it rules out is a length-aware or numeric comparator, and a different order is
  a different signature. §6.3¶2 makes a duplicate record "a protocol error" that MUST be treated as
  one, permitting leniency only on condition that all but one copy be dropped: both readings are
  honoured, `DuplicateRecordError` by default and `tolerate_duplicates=True` doing the drop,
  because sorting two identical members produces a string no signer made.
  `canonical_wire()` is per-codec rather than one `bytes(...).lower()` on the whole record: an MX
  preference or an SRV port of `0x4142` is inside the A-Z byte range, and lowering it would corrupt
  the number while "canonicalising" — `test_canonicalisation_leaves_numeric_fields_alone` exists to
  keep anyone from taking the shortcut. A type that item 3 lists but this package has no codec for
  raises `CanonicalizationError` instead of hashing raw octets, because guessing where names sit
  makes a *valid* signature fail, which is indistinguishable from an attack.
  `signed_owner_name` does the §3.1.3 wildcard reconstruction (`www.example.com.` with Labels 2 is
  signed as `*.example.com.`), refuses a Labels value larger than the owner has labels rather than
  clamping it, and keeps the `*` in the hashed name as §3.1.3¶4 requires.
- RSA public keys in DNSKEY, and the width of an RSA signature (RFC 3110 §2-§3, RFC 5702 §2).
  `pack_rsa_public_key`, `unpack_rsa_public_key`, `rsa_signature_octets`, `RsaPublicKey` and
  `MalformedRsaKeyError` in `namespy/dnssec.py`; `RData_DNSKEY.key_algorithm_is_rsa`,
  `rsa_public_key()` and `require_rsa_key()` in `namespy/rdata.py`;
  `RSA_ALGORITHMS`, `RSA_MIN_KEY_BITS_BY_ALGORITHM` and `minimum_rsa_key_bits()` in
  `namespy/crypto.py`. Reading RFC 3110 turned up no reason to wait for the backend: §2 is integer
  packing, so the key material is now decodable on a default install while ECDSA and EdDSA still
  wait on `namespy[crypto]`.
  **The RFC's "leading zero octets are prohibited in the exponent and modulus" (§2¶3) is not
  tidiness — it is key-tag arithmetic.** A key tag sums the RDATA octets, so the same modulus and
  exponent written with a leading zero produce a different tag and therefore a DS that matches
  nothing: every bit correct, the key unusable. The same reasoning makes §2¶3's
  "is represented as" prescriptive about the 1-or-3-octet exponent length field, so
  `unpack_rsa_public_key` refuses a 3-byte exponent written in the long form rather than forgiving
  the second encoding. Both directions are tested, including the rare 256-octet exponent that
  reaches the 3-octet form at all.
  **`MIN_RSA_KEY_BITS` was not enough on its own, and the gap is a downgrade surface.** RFC 3110
  §3¶9 and RFC 5702 §2.1¶2 set the modulus floor at 512 bits for algorithms 5, 7 and 8, but
  **RFC 5702 §2.2¶2 sets it at 1024 for RSA/SHA-512**: one constant accepts a 512-bit RSA/SHA-512
  key that RFC 5702 forbids. Since a zone may hold keys of several algorithms and a validator picks
  one, the weakest key is what an attacker aims at, so the floor is now per-algorithm and
  `require_rsa_key()` looks it up. `MIN_RSA_KEY_BITS` remains as the general floor with a pointer
  to the function.
  Algorithm 1 (RSA/MD5) is deliberately *not* read with this format. RFC 3110 §2's notes moved
  RSA/SHA-1 onto number 5 specifically to separate it from RFC 2537's RSA/MD5 keys, whose RDATA
  begins with a key-length header that this parser would take for an exponent length and return a
  plausible wrong key. `RSA_ALGORITHMS` is derived from the existing algorithm table rather than
  written out again, so the two cannot drift.
  **Erratum 2811 is why `rsa_signature_octets` pads instead of rejecting.** RFC 3110 §3¶10 as
  published said "leading zero bytes are permitted" in an RSA signature; the verified technical
  erratum changes it to "MUST be added ... so that the signature size in bytes is equal to the size
  of n", citing PKCS #1's `I2OSP(s, k)`. Records written against the published wording exist, and
  a backend handed a short signature fails in the same shape as a forgery, so a short signature is
  padded and a signature *wider* than the modulus is refused — that one cannot come from a
  reduction mod n, so trimming would be guessing.
  Parsing behaviour is unchanged: a DNSKEY holding unreadable RSA octets still parses, still
  computes its key tag, and refuses only when `rsa_public_key()` is asked, which keeps RFC 4034
  §2.1.2's "judged at verification time" and keeps an operator's ability to say which rule a zone
  broke.
- Cached denials now keep their proof records. `NegativeEntry` gained a `proofs` field — the
  NSEC/NSEC3 RRs that denied the name, each followed by the RRSIGs covering it — stored by both
  backends and readable from both lookups, including `nxdomain_at`, the one that answers a name
  nobody queried. `namespy.nsec.collect_proof_records(records)` builds the bundle, and
  `namespy.nsec.proof_entries(records, rtype)` adapts wire records into the `(owner, rdata)` pairs
  the proof predicates take, so `closest_encloser_proof` can now be fed straight from a response or
  from the cache.
  **The bundle is defined by RFC 4035 §3.1.1¶3, not by convenience**: "When placing a signed RRset
  in the Authority section, the name server MUST also place its RRSIG RRs in the Authority
  section." A collector that returned bare NSEC records would let a resolver hand a client an
  authenticated-looking denial from the one server the client trusts, so a proof with no covering
  RRSIG is dropped rather than half-stored. Pairing is by owner name and Type Covered — never by
  Signer's Name, which is the zone apex and in an NSEC3 response resembles neither the denied name
  nor anything else. That distinction is a test of its own, because pairing on the signer is the
  natural implementation and it fails exactly where proofs matter.
  `proof_entries` deliberately does *not* require signatures, and the difference from the collector
  is documented on both: one answers "what does this set assert", which a diagnosis needs even for
  records it will not trust; the other answers "what may be echoed as authenticated".
  SQLite needed a column, and a column needs a migration that schema text cannot do: `CREATE TABLE
  IF NOT EXISTS` is a no-op against a file that already exists, so an on-disk database from an older
  build has no `proofs` column and every read would raise `OperationalError`. `_add_proofs_column`
  checks `PRAGMA table_info` and ALTERs once; old rows read back with no proofs, which is the truth
  about them, and new writes carry them. An unreadable proofs blob costs the proofs and not the
  denial — the same degradation `_decode_soa` already applies, for the same reason: deleting the
  entry would turn a missing signature bundle into a re-query storm.
  **What is not claimed, in one sentence because it is the interesting part: the resolver still does
  not echo these records, because it never sets the DO bit and so is never sent them.** RFC 4035
  §3.2.1 is blunt that "the resolver side of a security-aware recursive name server MUST set the DO
  bit when sending requests, regardless of the state of the DO bit in the initiating request", and
  that the name-server side MUST strip DNSSEC RRs when the client did not ask but MUST NOT strip
  types the query explicitly requested. Honouring that pair needs the client's DO state carried
  into the resolver and an OPT record built with DO on outbound queries — done in the entry below,
  which turns RFC 8020 §2¶5's MUST from storable into satisfiable. Proofs that do arrive
  — from a caller that queried DNSSEC types explicitly — are collected, cached and reachable today.
- Outbound DO, and the DO/AD confusion that was hiding behind a property name.
  `RecursiveResolver(dnssec_ok=True)` sets EDNS(0)'s DNSSEC OK bit on every query (new
  `namespy.packet.EDNS_DO_BIT` / `EDNS_CD_BIT` constants, used by the readers), which is what makes
  the proofs above arrive at all — an authoritative server sends NSEC/NSEC3 records to a resolver
  that asks for them, and RFC 4035 §3.2.1 is explicit that "the resolver side of a security-aware
  recursive name server MUST set the DO bit when sending requests, regardless of the state of the DO
  bit in the initiating request". Off by default and deliberately so: that MUST binds the recursive
  *name server* serving DNSSEC-aware clients, and this package is a resolver library until a caller
  makes it one; the option costs octets per query and can force a TCP re-ask, so it is an operator's
  decision rather than a default. The EDNS fallback path drops DO along with the OPT record it is
  re-asking without, so a server that rejected EDNS is not asked for DNSSEC data a second time.
  **`DnsMessage.ad` was reading OPT FLAGS bit 15, which is DO, not Authentic Data.** AD is header
  bit 5 (RFC 6895) and asserts "this responder validated the answer"; DO is a *request* — "please
  include DNSSEC records" — and an authoritative server echoes it back in its response OPT whether or
  not anything was authenticated. The property is now `DnsMessage.dnssec_ok`, and the consequence is
  user-visible: `namespy lookup` printed `ad` in the header flag list from that bit, so **every
  response from a DNSSEC-aware server claimed "authenticated data" to a CLI that had not verified a
  single signature.** The header flags list no longer prints it, and `_opt_flags` now reports the
  bit where it belongs and by its right name — `flags: do` on the EDNS line, as dig does.
  The header's own AD and CD bits are not modelled by this package's wire format yet, so there is
  currently no correct source for an `ad` flag at all; printing nothing is the honest answer until
  they are, which is now a roadmap item — and a prerequisite for RFC 5155 §9.2's AD prohibition,
  which cannot be obeyed by a resolver that cannot set the bit.
- The serving rule that makes the request worth making: the proof echo a DO=1 client is owed, and the
  strip a DO=0 client is owed. `namespy.dnssec.DNSSEC_SECURITY_TYPES` (RRSIG, DNSKEY, NSEC, NSEC3,
  NSEC3PARAM) is the set RFC 4035 §3.2.1¶1 makes conditional on the client, and
  `DnsServer._strip_dnssec` withdraws it from every section of a reply — recomputing the header
  counts, which are stored rather than derived, so an answer that drops two RRSIGs while still
  claiming four records is a message lying about its own length. `_synthesize_response` attaches a
  cached denial's stored proofs to its answer, which is what makes RFC 8020 §2¶5's MUST satisfiable
  rather than merely storable: "the iterative, caching resolver MUST return these NSEC or NSEC3
  records in the response to the triggering query if the query had the DNSSEC OK (DO) bit set". The
  guard deciding whether to strip exists in exactly one place — `_reply`, just before `_apply_edns` —
  so the resolver assembles the full answer, the cache never loses evidence, and no policy is split
  across two components. Three readings the spec leaves open are recorded in the code and tested:
  **QTYPE=\* is not an explicit request for RRSIG** (§3.2.1's exception covers types a query
  "explicitly requested", and RFC 3225 §2¶5 makes client willingness binary — otherwise one wildcard
  type defeats the strip, to the benefit of nobody, since §2¶3's resolvers that fail on DNSSEC records
  are precisely the ones that send ANY); **a QTx in RFC 10029's list counts as explicitly requested**,
  because a client that named RRSIG among the types it wanted asked for that type, whichever option
  carried it; and **DS is not in the set**, on the reading that it is data rather than decoration.
  That last choice has an operational consequence — a DO=1 walk can now carry a DS in a referral on to
  a DO=0 client, which §3.1.4's referral rule arguably wants and RFC 3225 §2¶3 would rather avoid —
  so it is filed as an open question on the roadmap instead of being presented as settled.
  `namespy lookup --dnssec` puts the whole path within reach of a user: DO outbound, signatures and
  proofs printed, and a `namespy serve --dnssec` operator gets both halves of §3.2.1. A known gap: the
  SOA that rides along with an echoed denial is unsigned, because an RRSIG over the SOA is not a proof
  of anything and was never stored with the proofs. `tests/test_dnssec_serving.py`, 12 tests over the
  echo, the strip, both exceptions, and the funnel.
- Authenticated denial of existence: the NSEC and NSEC3 proof rules, in a new module
  `namespy/nsec.py` (RFC 4034 §6.1, RFC 4035 §5.4, RFC 4592 §3.3.1, RFC 5155 §6-§9).
  `name_order_key`, `canonical_name_before`, `sort_canonical`, `name_between`, `hash_between`,
  the NSEC predicates (`nsec_matches`, `nsec_proves_nxdomain`, `nsec_proves_no_type`,
  `nsec_proves_no_wildcard`, `nsec_owner_is_explicit`, `find_nsec_matching`,
  `find_nsec_covering`), the NSEC3 predicates (`nsec3_owner_digest`, `nsec3_matches`,
  `nsec3_covers`, `nsec3_proves_nothing`, `nsec3_proves_no_type`, the two finders, `usable_nsec3`,
  `nsec3_record_is_from_proper_zone`), the §8.3 algorithm as `closest_encloser_proof` returning a
  `ClosestEncloserProof`, `wildcard_at`, and §8.4's full Name Error check as
  `nsec3_proves_nxdomain` returning an `Nsec3NxdomainProof`. Like the canonicalisation work, this
  authenticates nothing: it reports what a set of records asserts, and verifying those records
  remains the verification leg's job.
  **Two error types, because the two situations ask the resolver for opposite things.** An
  `IncompleteProofError` means the records were not in the response, which RFC 4035 §5.4¶6 says a
  resolver MUST act on by asking again — typically over TCP, since truncation is what drops proof
  records, and the third record of an NSEC3 denial is the one usually lost. A
  `ContradictoryProofError` means the records cannot all be true, where retrying is pointless and
  the answer is bogus. Collapsing the two is how a resolver ends up either hammering a server that
  is correctly refusing it, or accepting a forged denial because it retried its way to something
  that looked better.
  **The span has to wrap, and the naive reading of a zone's last record silently breaks it.** The
  last NSEC points back at the apex (RFC 4034 §4.1.1¶1) and the last NSEC3 back at the first hash
  (RFC 5155 §7.1¶19), so its second endpoint sorts *before* its first. Compare them the obvious way
  and that record appears to cover nothing: every name after the zone's final owner — which is what
  a passer-by probes, since it is where the chain ends — comes back unproven, and a legitimate
  NXDOMAIN is reported as bogus. `name_between` and `hash_between` both carry the wrap branch, and
  the single-owner-name case (endpoints equal, span covering everything else) falls out of the same
  expression rather than needing its own rule.
  Two bitmap rules are MUST-NOT-reads that implementations commonly get wrong in the permissive
  direction: RFC 4035
  §5.4¶7 requires ignoring the NSEC and RRSIG bits in an NSEC RR, because a validated NSEC already
  proves both exist at its owner name — so a signer that left them out of the bitmap must not be
  able to have it disprove the record carrying it; and RFC 5155 §7.1¶5 means a signed zone never
  lists NSEC3 in its own Type Bit Maps, so the same reasoning excludes that bit. §8.5¶2's related
  case — an empty non-terminal's record has an *empty* bitmap and correctly denies everything — is
  tested as well.
  **`closest_encloser_proof` implements RFC 5155 §8.3's algorithm literally, including an
  asymmetry that is easy to "simplify" into a bug.** The flag means "the name one label longer is
  covered", it is cleared only when a name has no matching record, and it survives the step up to
  the parent — which is the whole point, since the encloser is found by inheriting the flag its
  child raised. A name that matches while the flag is clear is *bogus* (§8.3¶10), not merely
  unhelpful: the server is denying a name it has just proven exists. §8.3¶12's proper-zone test is
  applied to the encloser's record — a DNAME there, or an NS without an SOA, means this server is
  not authoritative below the name it is denying, so the proof denies nothing however well signed.
  §8.4 then requires the wildcard at the encloser to be covered as well, which is the half that
  stops a server denying `hostile.example.com.` on the strength of having no such name while a
  `*.example.com.` answers for it. RFC 4592 §3.3.1¶4 is what makes that a single name to test
  rather than a wildcard search, and §3.3.1¶6-¶7 the reason no "closest wildcard" fallback exists.
  `usable_nsec3` applies §8.1 (ignore unknown hash algorithms) and §8.2¶1 (ignore Flags other than
  zero or one) as filters, then refuses mixed algorithm/iterations/salt sets under §8.2¶2's MAY:
  hashes from different parameters are not comparable, so a mixed set lets a server pair a matching
  record with a covering record computed differently and produce two proofs that together prove
  nothing. Opt-Out spans get `nsec3_proves_nothing` (§6¶3 — an Opt-Out record asserts nothing about
  what it covers, and reading it as a denial is the attack rather than an optimisation) and
  `ClosestEncloserProof.via_opt_out`, which is how the resolver will know not to set AD when
  RFC 5155 §9.2¶1 forbids it.
  **Not claimed.** §8.5's amended text from **erratum 3441** (a No Data response caused by an empty
  non-terminal under an Opt-Out span must carry the closest provable encloser proof) belongs with
  the No-Data validators, and §8.6-§8.9 (DS no-data, wildcard no-data, wildcard answers, referrals
  to unsigned subzones) are not implemented yet; neither is any of this wired to a `DnsPacket`,
  which needs the cache to hold proof records alongside a negative answer.


### Fixed

- **A correctly signed RFC 5155 §8.7 wildcard No Data answer over NSEC3 was
  judged Bogus, and the walk SERVFAILed it.** Where the chain held no record
  matching QNAME and the next-closer record *asserted*, `_nsec3_no_data` read
  §8.5 alone and convicted the response — but the assertion proves exactly
  §8.7's precondition (the name does not exist; a wildcard at the closest
  encloser, its matching record's bitmap lacking QTYPE and CNAME, is what makes
  No Data the right answer instead of Name Error). The NSEC engine's
  RFC 4035 §5.4¶6 branch has adjudicated that shape its whole life;
  `aggressive.py` knew §8.7 for the cache path, which is why the suite stayed
  green while the wire path was blind. The asserting span is now the hinge into
  §8.7 — shared tail between the two entry points, refusals unchanged in kind:
  a response denying its own wildcard holds the two records of a Name Error,
  and a response proving neither way is truncation, a retry. §8.7 names no
  QTYPE exception, so a DS NODATA at a denied name rides the shape too — what a
  clear bit under a proven wildcard can never mean is a *secure* delegation,
  and parity with the NSEC engine is what the chain builder's answers now hold.
  Two refusal tests re-pinned to the reason §8.7 owns (same Bogus verdict,
  truer citation), three shape tests, one validator scenario, and one scripted
  walk added — the last is the defect's proof-of-death end to end: the answer
  now arrives NODATA, SECURE, AD, cached and validated
  (`namespy/nsec.py`; `tests/test_nsec_responses.py`,
  `tests/test_dnssec_validate.py`, `tests/test_dnssec_wiring.py`).

- A wire record whose RDATA is structurally well-formed but semantically impossible — an RRSIG whose signature field is zero octets, an empty DNSKEY public key, a zero-length DS digest, an NSEC3 hash the wrong length for its algorithm — escaped the parser as the codec constructor's bare `ValueError` instead of `DnsPacketParseError`, breaking the invariant the wire-fuzzing property is built to guard ("malformed input surfaces as one class the reader already catches, nothing else") and letting one corrupt octet crash the parse path. `DnsRecord.parse` now converts `ValueError` raised inside any codec's `parse_from` into `DnsPacketParseError` at the one boundary every codec crosses (namespy/packet.py; constructors keep raising `ValueError` for API callers, where a wrong field is a programming error, not a datagram). Found by `test_one_corrupt_octet_never_brings_down_the_parser` replaying a real counterexample; pinned by `test_an_rrsig_with_an_empty_signature_fails_the_parse_not_the_process`.

- **The Indeterminate state was cited to the wrong RFC.** Documentation written while
  building `namespy/verify.py` and `namespy/crypto.py` credited the four validation states
  to "RFC 9080 §3.1" — but RFC 9080 is the Homenet profile of the Babel routing protocol,
  and the citation survived two rounds of review because nobody opened the document.
  Re-checked against the source: the states are RFC 4035 §4.3's, with the variant wording
  in RFC 4033 §5 and both reprinted side by side in RFC 9499 §11. All eight occurrences
  (module docstrings, two enums, one test, the changelog, the handoff, the roadmap) now
  cite §4.3, and rule 8 acquired its scar tissue.

- **The name round-trip fuzzer could raise instead of skipping.**
  `test_names_survive_encode_parse_and_back` assumed the 255-octet limit away *after*
  encoding — `assume(len(bytes(name)) <= MAX_NAME_OCTETS)` — and the encoding is exactly
  what raises `DomainNameError` once the budget is blown, so the assumption guarded
  nothing and a stored six-label counterexample (39-to-40 octet labels) turned every
  local run red while CI's fresh `.hypothesis/` database and lower example count stayed
  green. The bound is now computed from the label octets before `from_labels` can raise,
  and the same ordering mistake in the unregistered-types property (the 0xFFFF record
  budget) is fixed the same way.

- **Ten test fixtures held an HTTPS record that cannot be parsed.** The octets
  `b"\x00\x00\x00\x01"` were used as HTTPS RDATA across `test_bundle.py` and
  `test_resolver_mqtype.py`: priority 0, target `.`, then one stray octet — and RFC 9460
  §2.2's first malformed condition is that "the end of the RDATA occurs within a SvcParam",
  which is exactly what a lone trailing octet is. Nothing noticed because no test round-tripped
  those records through the wire codec; the first thing that did was the new client-to-server
  interop test, and what it caught was the *client* discarding a complete, correct reply
  because the record inside it was malformed. They now carry a real minimal record (priority 1,
  target `.`, `alpn=h2`).
- **`docs/rfc-map.md` said EDNS(0) was decoded but not sent.** Outbound OPT has been sent for
  several rounds — advertised payload, `extended_rcode`, `ad`/`cd`, the §6.2.2 unextended
  re-ask, and NSID, EDE and MQTYPE options in use — while §11 still told a reader that outbound
  queries carried no OPT and that the payload ceiling was therefore 512 octets and the RCODEs
  still 4 bits. The bullet now describes what is actually partial about it (which options are
  put on the wire, and why COOKIE and Padding are not), and §10 gained the code-mapping rows
  those features never got: option TLVs and per-server payload sizes, Extended DNS Errors,
  MQTYPE in both directions, SVCB parameters, and the QNAME minimisation schedule.

### Changed

- **EDNS OPT flags bit 14 is CO, not CD — a wire constant retired against the live
  registry.** `packet.py` documented `EDNS_CD_BIT = 1 << 14` as "Checking Disabled,
  OPT FLAGS bit 14 (RFC 6891 section 6.1.3, RFC 6955 section 4)" — and neither
  citation holds: RFC 6891 §6.1.3 draws the flags field as fifteen reserved bits
  under DO's bit 15, and RFC 6955 §4 is *Static DH Proof-of-Possession*, a
  document in no DNS registry. The IANA "EDNS Header Flags (16 bits)" registry
  (fetched 2026-10-16, checked against `dns-parameters.xml`) has never held a CD
  entry: its rows are Bit 0 DO, Bit 1 CO (RFC 9824 — registered 2025-03-06), Bit 2
  DE (temporary, draft-ietf-dnsop-delext), Bits 3-15 Reserved; its numbering runs
  from the top, so "Bit 0" is the 6891 drawing's bit 15 and CO's "Bit 1" is the
  same physical 0x4000 as RFC 9824 §5.1's `|DO|CO|` picture — §9's table and §5.1's
  drawing agree once the registry's direction is known. `EDNS_CD_BIT` and the
  `cd` property are replaced by `EDNS_CO_BIT` and
  `DnsPacket.compact_answers_ok`; the response's *header* CD (bit 4, RFC 4035
  §3.2.2 — the CD this protocol actually speaks of) was always a separate
  attribute and is untouched, as is everything that reads it. The property's only
  consumer, the CLI's OPT-flags print, now prints `co` where it would have printed
  `cd` — against a real server, that print would have been reporting RFC 9824
  signaling under a flag that does not exist. Three assertions in
  `tests/test_edns.py`/`tests/test_packet_wire.py` re-pinned to CO. The same
  registry pass refreshed `edns.py`'s EDE table, whose comment claimed codes
  25-49151 unassigned since RFC 8914: seven have registered since (25 and 29 by
  vendor procedure, 26 by RFC 9250, 27 by RFC 9276, 30 by RFC 9824, 28 and 31 by
  their drafts); the names are copied verbatim from the live registry, and the
  test's sample "unassigned" code moved to 32.
- **The roadmap's 0x20 row closed unspecifiable.** The deferred-work list queued
  "0x20 encoding | 6841" on the strength of a title remembered; RFC 6841 is *A
  Framework for DNSSEC Policies and DNSSEC Practice Statements* (INFORMATIONAL),
  and no RFC — current, obsolete, or anywhere in between — specifies the
  case-randomization mechanism, whose only text was `draft-vixie-dnsext-dns0x20`
  (expired 2010; the corpus preserves just its bibliography entry, in RFC 8555).
  The row now says so and is closed; roadmap row "Every RFC citation checked"
  records the audit.

- **The coverage floor was not enforced anywhere.** `fail_under` in `pyproject.toml` is
  read by pytest through pytest-cov, and pytest-cov measures only when `--cov` is passed;
  the Test job ran plain `pytest -q`, so it exited 0 whatever the tests covered while the
  README, CONTRIBUTING and the comment above that floor all said it was enforced by
  pyproject. The step now runs `python -m pytest -q --cov`, and all three say so too.
  Verified in both directions: one test file exits 1 with "Required test coverage of 80.0%
  not reached", the whole suite exits 0 at 87.2%. The floor itself stays at 80 rather than
  moving to meet that figure — 87.2% was measured on one platform and one Python, CI gates
  on two of each, and a floor raised on a guess protects nothing.
- **`--trace` rendered every failure twice.** The `Fail` branch appended its note
  twice, so a reader counted one dead end as two. Fixed as part of giving glue
  observation somewhere to appear; `test_trace_mermaid.py` now pins the count.
- **Out-of-bailiwick glue is no longer believed (RFC 5452 section 6).** A
  referral's address records are accepted only for a nameserver name inside the
  zone that answered, or inside the zone that referral delegated -- RFC 1034
  section 4.2.1 makes a parent responsible for exactly that glue, and nothing
  else it volunteers is credible. Before this, any A/AAAA in the additional
  section was used, so a delegation could aim the rest of a lookup, and the
  queries sent while performing it, at an address of its own choosing. A
  discarded address leaves the nameserver as a name that needs resolving, which
  the existing `NeedAddress` sub-resolution satisfies from the servers that are
  authoritative for it (RFC 1034 section 4.2.2). Pinned by
  `test_resolver_classify.py`; the two-hop descent in `test_resolve_steps.py`
  now walks that sub-resolution instead of believing the volunteered address.
- Every RFC citation in the tree was re-checked against the published texts.
  The corrections were mostly to section numbers that do not exist or say
  something else: response matching is RFC 5452 section 9.1 (not 5), ID and
  source-port randomisation is section 9.2, in-domain acceptance is section 6,
  and RFC 5625 -- DNS Proxy Implementation Guidelines -- has no section 2.5 at
  all; its packet-filtering advice is section 6.3.
- **Record TTLs are now clamped to 2147483647 (RFC 2181 section 8).** The
  clamp existed as `clamp_ttl()` but was never called: a hostile or buggy
  server offering `0xFFFFFFFF` produced a cache entry that never expired,
  which is a poisoning half-win that lasts forever.
- **NS/CNAME/PTR/DNAME RDATA with trailing octets is refused.** Only the
  overrun direction was checked, so `RDLENGTH = name + garbage` half-parsed;
  MX, SRV and SOA already failed closed, and RFC 9267 section 5 says the
  whole declared length must be accounted for.
- **TXT with an empty RDLENGTH is refused** (RFC 1035 section 3.3.14: one or
  more `<character-string>`).
- **Interior empty labels are no longer silently erased.** `DomainName("a..b")`
  used to encode as `a.b`, collapsing two distinct names onto one wire form;
  the encoder now refuses, which is honest because no wire form for an
  interior empty label exists.
- **Compression pointer octets no longer count against the 255-octet name
  budget** — RFC 1035 section 3.1 bounds the expanded name, not the encoding;
  the old accounting rejected valid wide names carried on pointers.
- **Wire-parsed names carry their correct start offset** in `.offset` (it
  held the post-pointer resume point, or `None`).
- Non-ASCII digit-like characters in presentation names no longer raise
  `ValueError` from the `\DDD` escape decoder.
- Resolver IPv4 malformed-datagram logging dropped to `DEBUG`; the IPv6 path
  and the server already stayed quiet, and a `WARNING` + hex dump per spoofed
  datagram is a free log-flood primitive.
- **Cancelling an awaited UDP query releases its pending slot.** The timeout
  path popped it; cancellation — the common case on caller timeouts and
  reconnects — did not, growing the pending dict for the resolver's lifetime.
- **The server bounds task creation, not just concurrent lookups.** Under a
  datagram flood it previously minted one coroutine per packet before any
  semaphore; excess traffic is now dropped silently per RFC 5625 section 6.2.

- EDNS(0) on the wire (RFC 6891, full implementation at `HEAD`): OPT on
  every outbound query (§6.1.2) advertising a 1232-octet payload with the
  512 floor enforced (§6.2.3), the EXTENDED-RCODE | VERSION | FLAGS TTL
  layout and 12-bit RCODE reassembly (§6.1.3), the §7 FORMERR-without-OPT
  signature plus BADVERS/NOTIMP driving exactly one unextended re-ask
  (§6.2.2), and an OPT that is never cached (§6.2.1). `--no-edns` or
  `edns_payload_size=0` opts out entirely. Remaining EDNS work (options
  TLV, per-server payload adaptation, responder-side echo) is roadmap P1
  in [`docs/roadmap.md`](docs/roadmap.md).
- `docs/roadmap.md` — the specification-completeness matrix: every
  obligation the code could take on, status, and the test that pins it,
  consolidating into a prioritised roadmap. README links it as the
  project's planning document.
- `tests/test_edns.py` (17 tests) — the OPT on the wire, TTL bit layout
  against RFC diagrams, fallback matrix, cache exclusion, knob plumbing.

### Added earlier in this effort

- `LICENSE` — Apache-2.0. The repository previously had none, which meant
  "all rights reserved" by default and no one could lawfully use the code.
- GitHub Actions CI: lint, a 3.12/3.13 × Ubuntu/Windows test matrix, a run of the
  whole suite under `python -O`, and a distribution-audit job
  (`.github/workflows/ci.yml`). Dependabot for pip and Actions.
- A release workflow gated on `v*` tags, using OIDC trusted publishing. Dormant
  until the PyPI project and its `pypi` environment exist; see the comments.
- `tools/check_dist.py` — asserts a built wheel *and* sdist contain
  `namespy/named.root`, `namespy/py.typed` and the license text, and that generated
  files have not leaked in.
- `SECURITY.md`, `CONTRIBUTING.md`, `docs/rfc-map.md` (spec obligation → code →
  test), `docs/HANDOFF.md`, `docs/legacy/`.
- Tests: `test_names_wire.py`, `test_packet_wire.py`, `test_resolver_matching.py`,
  `test_resolver_alias.py`, `test_server.py`, `test_cli.py`, `test_enums.py`.
  Coverage went from unmeasured to 80%+ with an enforced floor; `server.py` was
  previously untested entirely.
- `RData_DNAME`, and CNAME/DNAME chain following in the resolver.
- `DomainName.from_labels()`, `DomainName.is_subdomain_of()`,
  `DomainName.is_hostname`, `DomainName.is_wildcard`, `RData_SOA.serial_ahead()`,
  `RData_TXT.from_text()` / `.text`, `RData_MX.is_null_mx`.
- `namespy/py.typed`, a `namespy` console script, and `[project.urls]`.
- `TC` now triggers a TCP retry. A UDP response with the truncation bit set, or a
  UDP attempt that times out, is re-asked over TCP to the same server
  (RFC 1123 section 6.1.3.2, RFC 7766 section 6). A truncated UDP answer is never
  returned, and no truncated response is ever cached — a partial RRset is
  indistinguishable from a complete one once stored (RFC 1035 section 7.4).

### Changed

- **Wire parsing no longer uses `assert` for bounds checks.** Everything on a
  network path raises `DnsPacketParseError`. The previous behaviour was that
  `python -O` removed every length check in `names.py`, `packet.py` and
  `rdata.py`.
- Compression pointers are validated the way RFC 9267 section 2 requires: the
  2-bit test is `(offset & 0xC0) == 0xC0` rather than `offset & 0b11000000`,
  reserved types `10`/`01` are rejected, targets must strictly decrease, and
  expanded names are capped at 255 octets counting label-length octets.
  Pointer-to-pointer chains — valid wire form that used to raise — now parse.
- RDATA is parsed inside its declared RDLENGTH (RFC 9267 section 5) instead of
  being sliced twice, which silently accepted a short RDATA and walked into the
  next record.
- Unknown RR types and classes decode to opaque `RData` per RFC 3597 section 3
  instead of raising `AttributeError` from a protocol callback. `DnsRType` gained
  `SVCB` (64), `HTTPS` (65), `CSYNC` (62), `ZONEMD` (63) and others;
  `DnsResponseCode` gained the EDNS(0) extended values.
- Responses are matched on source address + transaction ID + **question section**
  (RFC 5452 sections 5–6), not address + ID alone. A reply that omits the question
  section is no longer accepted.
- A non-authoritative `ANCOUNT == 0` response with NS records in the authority
  section is no longer classified as a referral when the authority section holds
  an SOA — the NODATA/NXDOMAIN distinction RFC 2308 section 2.2.1 requires.
- `RData_SOA` is serialisable (it previously raised `AttributeError` on `bytes()`,
  so any response containing an SOA could not be re-emitted), parses `MINIMUM`
  (RFC 2308 section 5), and compares serials with RFC 1982 wrap-around arithmetic.
- Name labels follow RFC 2181 section 11: any octet string is storable, with LDH
  checking moved to the opt-in `is_hostname`. `_dmarc.example.com`,
  `_smtp._tcp.example.org` (BCP 222) and `*.example.com` (RFC 4592) now parse.
- TTLs are clamped to 2147483647 when served (RFC 2181 section 8).
- The resolver no longer performs blocking network I/O in `__init__`. Root hints
  come from the packaged `named.root` via `importlib.resources`; refreshing is an
  awaited `refresh_root_hints()` call.
- `MAX_HOPS`, `MAX_DEPTH` and the query timeout became constructor arguments rather
  than module constants.
- `logging.Logger("resolver")` became `getLogger(__name__)`; malformed-datagram
  logging dropped to `DEBUG` so a garbage spray cannot use the log as an
  amplifier (RFC 5358 section 4.2). The per-datagram `print()` is gone.
- The Linux-only `IP_MTU_DISCOVER` setsockopt is platform-guarded; it previously
  raised inside `connection_made` on Windows.
- Protocol constants renamed to PEP 8 member names (`DnsQR.RESPONSE`,
  `DnsResponseCode.NO_ERROR`) so the tables read consistently; the wire mnemonics
  are preserved where RFC 1035 section 4.1.1 names the field itself.
- `record.rdata` is now always an `RData`. Hand-built records used to store the
  raw `bytes` the caller passed while parsed records held an `RData`, so
  `print(record.rdata)` showed a Python bytes literal on one path and RFC 3597
  section 5 form on the other, and consumers needed `isinstance` branches. The
  constructor now offers the octets to the registered codec and falls back to the
  opaque form when they do not decode, so `DnsRecord(name, DnsRType.SOA,
  rdata=b"")` still works and wrapping never changes the wire form — asserted for
  every registered codec by `tests/test_rdata_wrapping.py`.
- Package metadata: explicit `[build-system]` (hatchling), version `0.1.0` read
  from `namespy.__version__`, declared license, classifiers, coverage and lint
  configuration, `mypy` clean on `namespy`.

### Removed

- `RecursiveResolver.enumerate_nameserver_addresses()`, an undocumented public
  static helper with no callers and no tests. It paired every NS in a referral
  with any address record in the additional section that shared its name, with
  no zone context and therefore no way to apply the bailiwick rule above -- in
  other words, a ready-made way to reintroduce the bug that was just fixed.
  `classify()` is where a referral is consumed and it performs the check; a
  caller that needs the shuffled-server behaviour is served by `Slist`, which
  already shuffles its candidates (RFC 8106 section 2).
- `namespy/dns.py` (empty), `Forwarder` (a constructor that did nothing), the
  unreachable `self.resolver.db` references, and the committed `dns.sql` /
  `database.png` scratch — legacy SQL notes moved to `docs/legacy/`.
- Tracked generated files: `last_resolution.md` (in two places), `.cursor/plans/`.
  `.gitignore` now matches what is actually tracked.

### Known gaps

Tracked honestly rather than as a promise — full list with reasons in
[`docs/HANDOFF.md`](docs/HANDOFF.md):

- EDNS(0) *options* are implemented and several are put to use: NSID (RFC 5001) in
  both directions, per-server payload adaptation (RFC 6891 §6.2.3, §6.2.4), Extended DNS
  Errors (RFC 8914) composed and consumed, MQTYPE (RFC 10029) in both directions — the
  bundled server combines the QTYPEs a query names and reports which ones it folded in
  (§3.3–§3.4), and the resolver asks for them, reads what came back, and re-asks what did
  not (§3.2, §3.5) — and the bundled server answers an extended query with an OPT of its
  own (§6.1.1, §6.2.4).
  Still unused on purpose: COOKIE has no server-side state to validate a reply against,
  and Padding is never emitted because RFC 7830 §6 withdraws it from plaintext UDP, which
  is every transport here. No client subnet option (RFC 7871) and no transport keepalive
  (RFC 7828) — see `docs/roadmap.md`. Asking with MQTYPE is opt-in (`--mqtype`,
  `resolve_bundle`), so a lookup that did not ask for it still sends nothing a legacy
  server has never seen.
- No DNSSEC validation, no serve-stale (RFC 8767), no IDN/punycode
  (RFC 5891 / RFC 3492), no DoT/DoH (RFC 7858 / RFC 8484). QNAME
  minimisation (RFC 9156) ships opt-in — see *Added*.
