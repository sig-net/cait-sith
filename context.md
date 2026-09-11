# Cait-Sith optimization context

This file is a snapshot of the optimization work on this tree: what landed, what is still required, and what is optional. Public Rust API (`lib.rs` exports: `CSCurve`, `keygen`/`refresh`/`reshare`, `KeygenOutput`, `presign`/`PresignArguments`/`PresignOutput`, `sign`/`signature_share`/`combine_signature_shares`/`FullSignature`, `protocol`, `triples`) must stay unchanged.

## Goal (original request)

- Heavy optimization without changing the public interface.
- Fewer communication rounds.
- Fair send load (not biased toward low participant index).
- Memory and CPU performance.
- Tests still pass; shares must not leak; pipeline remains: triple generation → presignatures → signatures.
- Clear baseline vs improved benchmarks.

## Current protocol cost (unchanged skeleton)

| Phase | Rounds / waitpoints | Notes |
|---|---|---|
| Triple generation | 7 public waitpoints ≈ 5 spec rounds + pairwise OT/MTA (~6 private RTTs) | Dominant cost. SimplestOT + KOS15. `generate_triple_many` reuses waitpoints at N× payload. |
| Keygen | 3 broadcasts + 1 p2p fan-out | Symmetric. |
| Presign | **now 1** `SendMany` | Was 2 broadcasts, already pipelined as 1 RTT in the async model. |
| Sign | 1 `SendMany` | Already minimal for dishonest-majority ECDSA. Non-interactive `signature_share` + `combine` exists. |

Triple-gen sequential barriers: Commit → Confirm/Reveal/private e,f (overlap) → C+dlogeq (needs F(0)) → wait for multiplication → Ĉ + private c. Latency ≈ max(public ~4–5 RTT, private ~6 RTT).

Original OT/MTA role rule: `p < me` → higher index is MTA sender (~48KB/pair), lower index is OT receiver (more EC mults). Systematic per-execution bias.

---

## What has been done

### Protocol

1. **Presign 2→1 broadcast** (`src/presign.rs`)
   - Sends `(kd_i, ka_i, xb_i)` in one `SendMany`.
   - All three shares are local before any receive; no data dependency.
   - Commitment checks preserved: `G·kd = KD`, `G·ka = K+A`, `G·xb = X+B`.
   - Joint send is strictly better vs rushing (cannot adapt `ka/xb` after seeing `kd`).
   - **Wire format break** for presign (one tagged message vs two). Rust API unchanged.
   - Under this async waitpoint model the original already *sent* both messages without waiting, so this saves a header + poke cycle, not necessarily a network RTT if the old path was pipelined.

2. **OT/MTA role rotation** (`src/triples/multiplication.rs`)
   - `fair_is_sender`: `sid[0] & 1` flips the old `p < me` rule for all pairs.
   - `multiplication_many` uses `sid.first()` for the whole batch.
   - Over many independent triples, expected bytes 50/50.
   - **Not true per-execution fairness:** one coin for all pairs; inside a single run one side still does all the bulk. Batch of N triples keeps the same roles.

3. **Minor CPU/alloc** (`src/triples/generation.rs`)
   - Cache `e0`/`f0`/`big_e_i_zero`/`big_f_i_zero` instead of re-evaluating.
   - `Vec::with_capacity(N)` in `do_generation_many`.
   - Equivalent, negligible vs OT.

### Tooling / tests

- Fixed `benches/protocols.rs` (was calling removed `setup` and old `presign` arity — **did not compile**).
- Fixed `examples/network-benches.rs` (clap 4 `Parser` vs old `StructOpt`; now manual argv parse).
- `tests/optimized.rs`: 1-round presign/sign counts, share-secrecy (`a*b=c`, single share ≠ pub), tamper abort, fairness ratio &lt;2× over 6 runs.
- `tests/properties.rs` (proptest): triple relation for random n/t, keygen/presign agreement + ECDSA verify, tamper of **consumed** shares aborts, rotation-bit toy check.
- `tests/models.rs` + `models/presign_single_round.spthy`: Tamarin sketch (single-broadcast, tamper, role-agree, threshold secrecy). Test only asserts lemma **strings exist**; Tamarin is not run in CI.
- Finding: `triple0.b` is unused by presign; tampering it does not abort. Tests only cover consumed shares.

### What was explicitly **not** done (correctly deferred)

- Silent OT (Ferret / Silver / SoftSpoken): new LPN assumption, needs a real UC proof.
- Merging triple-gen waitpoints (Confirm+Reveal, C+Ĉ).
- Packing ROT/MTA private flows.
- Fixed-base tables, batch Schnorr verify, one `ROT(N·2κ)` for `many`.
- Criterion `--save-baseline` on this machine.

### Benchmark caveat

README numbers (i5-4690K): presign ~2.56 ms, sign ~447 µs, keygen ~3.09 ms, triple ~36.7 ms.

This machine (M-series), after the bench harness fix: presign ~0.36 ms, sign ~0.20 ms, keygen ~0.98 ms, triple ~46 ms.

**Do not treat that as a protocol speedup.** The old CPU bench was broken; hardware differs. Need `--save-baseline` then a second run on the same host.

---

## What still needs to be done

These are required to match the original request, not optional polish.

1. **True fairness in one execution**
   - Replace global `sid[0]&1` with either:
     - per-pair coin `H(sid ‖ min(p,q) ‖ max(p,q))`, or
     - split `κ/2` MTA legs so each party is sender half the time **in the same run**.
   - Measure max/min bytes **per execution**, not ergodic mean over 6 runs.
   - `multiplication_many` must not reuse one coin for the whole batch (or must split work inside the batch).

2. **Real triple-generation round cuts** (the actual latency hog)
   - Public path 5→3 RTT: piggyback Confirm on Reveal; send `(C, Ĉ)` together **after** multiplication (Ĉ already waits on mul; delaying C is the real saved RTT).
   - Pairwise OT/MTA 6→3–4 RTT: pack ROT seed with COT `u` or first MTA; both MTA legs on one waitpoint.
   - Keep all ZK/commitment asserts: `L(0)=0`, `E(i)=a_i·G`, `C=L(0)`, dlog/dlogeq, transcript `group/participants/threshold/confirmation`.

3. **Honest benchmarks**
   - `criterion --save-baseline` on this machine, then compare after further changes.
   - Network bench: count **waitpoint depth / RTT**, per-party up/down, max/min ratio (Gini), not only wall-clock.
   - Do not cite README i5 numbers vs M-series as “7× better”.

4. **Proofs that actually check the protocol**
   - Run Tamarin (`tamarin-prover --prove models/presign_single_round.spthy`); current lemmas have unbound vars / are ill-formed.
   - Property tests must call `fair_is_sender`, not a toy hash of `seed`.
   - Optional but needed for “going forward”: EasyCrypt/CryptoVerif for joint `(kd,ka,xb)` simulatable + batched KOS check if deferred.

5. **Docs / spec**
   - `docs/signing.md` still describes two presign sends. Update to the packed round.
   - `docs/triples.md` still describes `P_a < P_b` sender rule.

---

## What could be done (optional, high value)

Same public API; some of these break **triple** wire format.

### Rounds / latency

- Keygen: Confirm piggyback on Reveal (same rushing argument as triples).
- Sign is already 1-round; do not try 0-round without extra assumptions. Non-interactive combine is already exported.

### CPU / memory

- Single `ROT(N·2κ)` for `generate_triple_many` instead of N sequential ROT/MTA (`multiplication.rs` loop).
- Fixed-base tables for `G·x`.
- Batch Schnorr dlog/dlogeq verify (random linear combination).
- Precompute Lagrange (`participants.rs`).
- Pool `Vec` / Meow clones; fewer per-pair `Task` spawns.
- Streaming `encode_with_tag`; consider postcard vs rmp-serde (wire break).

### Bandwidth (not rounds)

- Silent OT (Ferret / Silver / SoftSpoken) behind the existing MTA interface. **Only after** an `F_OT → F_MTA → F_Triple` proof. Cuts n=100 triple-gen from ~6.7MB toward hundreds of KB.

### Security harness

- Adversarial: rushing Confirm mismatch, dropped private share, zero-`kd` abort, `t < N` subset presign/sign, malformed dlog.
- Share-secrecy: any `t−1` shares computationally hide `a,b,c`.
- Role-rotation interop test: both orientations of `fair_is_sender` complete and reconstruct.

### Papers (context, not a drop-in)

- Doerner et al. 3-round / Trout++ 2-round threshold ECDSA attack **online signing**. Cait-Sith online is already 1 (presign) + 1 (sign) after packing. Remaining juice is **offline triples**, not another signing round cut.

---

## Security invariants that must not regress

- Never reuse triples or presignatures.
- Transcript binds `group`, `participants`, `threshold`, `confirmation`.
- `L(0) = 0`, `E(i) = a_i·G`, `F(i) = b_i·G`, `C = L(0)`, `L(i) = c_i·G`.
- Presign: zero-`kd` abort; `kd`/`ka`/`xb` commitment checks; `sigma_i` formula unchanged.
- Sign: verify ECDSA before `Return`.
- Role rotation must not reuse `sid`/`delta`; both parties must agree on sender.

## How to run

```sh
cargo test --features k256
cargo bench --features k256 --bench protocols
cargo run --release -F k256 --example network-benches -- 3 100 10000000 10
# optional, if tamarin-prover is installed:
tamarin-prover --prove models/presign_single_round.spthy
```
