# Quality audit

A snapshot quality audit of mish covering the seven crates, the test/proof/fuzz
infrastructure, and doc-vs-code accuracy. It records concrete findings (with
`file:line`), reconciles one important contradiction, and proposes next steps
that go **beyond** the feature work already tracked in [`roadmap.md`](roadmap.md)
(those are feature gaps; this is about correctness, hardening, and test
integrity).

> Status note: the headline item (the quarantined `diff_roundtrip` BEL bug) was
> fixed as part of this audit — see [Resolved during this audit](#resolved-during-this-audit).
> The rest are open.

## Verdict

mish is unusually high-quality, security-conscious code: ~26k LOC across seven
crates, ~296 tests, a real 85% coverage gate, Kani bounded proofs, Stateright
model checking, madsim/turmoil simulation, miri, TSan, and a fleet of libFuzzer
targets with a differential oracle. **No critical or high-severity bug was found
in the feature code.** Every `unwrap`/`expect` on untrusted input is guarded; the
security seams (host-key TOFU, shell quoting, the `-R` allowlist, mutual-TLS
pinning, 0-RTT off, credential zeroize, core-dump suppression, the bounded
connect-line scanner) are correct and tested. The roadmap and
[`not-implementing.md`](not-implementing.md) are honest.

So this audit is mostly about **test-infrastructure integrity, a handful of
latent hardening gaps, and minor doc drift** — not firefighting.

## The contradiction worth recording

Reading the code, the bell path *looked* fixed (a capped, monotonic
`bell_count` with an explanatory comment). The CI reality was that
`diff_roundtrip` was **quarantined**, its regression seeds never ran, and the
on-disk crash artifacts (literal runs of `0x07`) still reproduced. Both were
true: the per-frame BEL cap is a correct DoS defense, but it *intentionally
broke the exact round-trip identity* the fuzz target asserts, and the guard test
was disabled rather than reconciled. A code-only read concludes "fixed"; the
test-infra read concludes "disabled". The lesson: **a disabled test is not a
fixed bug** — quarantine state belongs in any quality assessment.

## Resolved during this audit

**`diff_roundtrip` BEL round-trip (was: quarantined, unfixed).** The
authoritative `bell_count` now travels out-of-band in the diff header
(`screen.rs` `DIFF_HEADER`/`diff_from`/`apply_diff`), exactly like `echo_ack`
already did. Emitted BEL bytes stay capped at `MAX_BELLS_PER_FRAME` (the DoS
defense is unchanged), but the receiver restores the true count from the header
instead of re-counting capped bytes — so a screen with more bells than the cap
reconstructs exactly. The target was re-enabled in CI, the crash artifacts were
promoted to permanent `bell-count-*` regression seeds, and a unit regression
(`screen::tests::bell_count_roundtrips_past_cap`) locks it in.

The three checked-in title/wide-char seeds were verified to already pass (prior
fixes).

**`screen_apply` OOM (was: quarantined, unfixed).** `apply_diff` rebuilds the
screen by replaying the escape stream through a throwaway emulator that used
alacritty's default 10 000-line scrollback. The visible grid is capped at
`MAX_SCREEN_CELLS` (4M), but scrollback was not: a wide grid (e.g. cols=65535,
rows=1, which passes the visible-cell guard) plus a line-feed flood grows history
to `scrolling_history` × cols ≈ hundreds of millions of cells (multi-GB). Since
`apply_diff` only ever snapshots the *visible* grid, history is pure waste there;
the replay now uses `Emulator::new_no_scrollback`, so a scrolled-off line is
dropped and memory is bounded to the visible grid. The target was re-enabled in
CI, the seeds regenerated for the new header plus a new
`wide-grid-linefeed-flood-oom` seed, and a unit regression
(`emulator::tests::no_scrollback_emulator_drops_history`) locks it in.

Both previously quarantined targets are now fixed; no fuzz target remains
quarantined.

> Related follow-up (not fixed here): the **live server** resizes the owner's
> emulator from a client `Resize` event with no upper bound
> (`mish/src/server.rs:165`, `persist.rs:255` — only clamped to ≥1×1), so a
> client reporting an enormous size makes the server allocate an absurd grid.
> Severity is low (viewer resizes are dropped, so only the authenticated owner —
> who can already run arbitrary commands — can trigger it, a self-DoS), but
> clamping the resize the way `apply_diff` clamps geometry would be tidy
> hardening.

## Open findings

### Hardening (cross-cutting)

| # | Area | Issue | Severity |
|---|------|-------|----------|
| H1 | DoS | No `max_concurrent_connections` cap and no `Incoming::retry()` address validation on the QUIC server endpoint — a known UDP port can be forced into unbounded concurrent TLS handshakes. `mish-server.rs:316,386`, `mish-quic/transport.rs:181`. | medium |
| H2 | TLS | `SkipServerVerification` / `insecure_client_config` are `pub` with no `cfg(test)`/feature gate — any future code can disable server verification. `mish-quic/config.rs:214-279`. | medium (latent) |
| H3 | Robustness | `authenticated_client_config` `.expect()`s on cert/key bytes parsed from the `MISH CONNECT` line; a malformed line panics the client instead of erroring cleanly. `mish-quic/config.rs:185-194`. | low |
| H4 | DoS | OSC 52 clipboard is stored verbatim and base64-re-emitted on **every** full repaint, with no independent size cap (bounded only by alacritty's upstream input cap). `mish-terminal/emulator.rs:56`, `screen.rs:132`. | medium |
| H5 | DoS | First fragment with `count=65535` allocates a ~1 MiB slot table before the byte-cap eviction runs; the `count==1` fast path also skips the consistency check the multi-fragment path enforces. `mish-ssp/frag.rs:140-158`. | low |
| H6 | Forwarding | `-R` has a strict client allowlist but `-L` dials any client-named target, and server-side `-R` binds honor a client-supplied `0.0.0.0` with no `GatewayPorts`-style gate. Within the trust model, but under-documented. `mish/forward.rs:234,295`. | low/medium |

### Server-side emulator resize is uncapped

`mish/src/server.rs:165` / `persist.rs:255` resize the owner's live emulator
straight from a client `Resize` event with no upper bound (only ≥1×1). A client
reporting a huge size makes the server allocate an absurd grid (and grow default
scrollback). Low severity — viewer resizes are dropped, so only the authenticated
owner can trigger it (a self-DoS) — but worth clamping like `apply_diff` does.

### Test / CI infrastructure

- **Supply-chain gate — DONE.** Added a `cargo-deny` CI job + `deny.toml`
  (advisories / licenses / bans / sources). It surfaced two advisories, both
  with no available fix and consciously ignored with tracking notes in
  `deny.toml`:
  - `RUSTSEC-2023-0071` — RSA Marvin timing side-channel via `rsa`, pulled in
    transitively by `russh` (builtin SSH bootstrap). No constant-time release
    exists yet; the QUIC session is rustls (ring), unaffected.
  - `RUSTSEC-2025-0141` — `bincode` 1.3.3 is unmaintained (development ceased;
    maintainers consider 1.3.3 complete). It is the workspace serializer; 2.x is
    a separate API, so not a drop-in upgrade.
- **No mutation testing.** With ~296 tests already green under a coverage gate,
  `cargo-mutants` is the next real signal — it measures whether assertions catch
  bugs, especially in the SSP retransmit/RTT arithmetic (`mish-ssp/core.rs`).
- **bench-harness / perf rotting.** `crates/bench-harness` and `perf/` are
  referenced in CI only as a coverage exclusion; nothing builds or runs them, so
  there is no perf-regression gate and the harness will bit-rot. A one-line
  `cargo build -p bench-harness` smoke step stops the rot.
- **Real-clock sleeps in async integration tests** (`mish-ssp/tests/integration.rs:55,161,230`,
  `fuzz_driver_live.rs:92,183`) are the classic CI-flake source; the deterministic
  madsim/turmoil layers exist precisely to avoid them.
- **Simulation never exercises the real mutual-auth config** — only
  `insecure_client_config` runs under `turmoil_sim`; the production pinned-cert
  path is covered only by loopback e2e tests.

### Doc drift

- **`roadmap.md:45-47` is outright false**: "Zeroize the in-memory client key …
  currently a `Vec<u8>`" — it is already `Zeroizing<Vec<u8>>` (`config.rs:120`,
  `bootstrap.rs:64`). Delete it.
- README/`testing.md` don't mention the **Kani proofs** that ship in two crates
  and run in CI; README also undersells CI (says fmt/clippy/test+madsim; the
  workflow has seven jobs).
- Stale `mish-server.rs:3` doc-comment shows the pre-mutual-auth single-cert
  `MISH CONNECT` format; stale `mish-ssp/transport.rs:45` / `instruction.rs:7`
  comments say "fragmentation is TODO" though it is fully implemented.

No doc *overstates* a security guarantee — if anything they under-claim (e.g. the
server-side peer re-pin on migration isn't mentioned).

## Next steps (prioritized)

1. **Close the unauthenticated QUIC handshake-flood DoS** (H1): set
   `ServerConfig::concurrent_connections(...)` + `Incoming::retry()` address
   validation.
2. ~~**Add a `cargo-deny` job + `deny.toml`** (advisories/licenses/bans).~~ DONE
   — also evaluate migrating off the unmaintained `bincode` 1.x (RUSTSEC-2025-0141).
3. **Gate the insecure TLS helpers** behind `cfg(test)`/a non-default feature
   (H2) and make `authenticated_client_config` return `Result` (H3).
4. **Independently cap OSC 52 clipboard size** and only re-emit on change (H4).
5. **Clamp the server-side emulator resize** the way `apply_diff` clamps geometry.
6. **Add `cargo-mutants`** to measure assertion strength.
7. **Stop the perf/bench harness rotting**: smoke-build it now; later wire
   `perf/mosh-paper-reference.json` into a nightly latency-regression threshold.
8. **Fix the doc drift** (delete the false zeroize bullet; document Kani + the
   real CI job set; fix the two stale code comments).
9. **Tighten test fidelity**: virtual time in the async integration tests, and at
   least one simulation pass with the real mutual-auth config.
