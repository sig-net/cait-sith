# Models

## `presign_single_round.spthy`

Symbolic (Dolev-Yao) model of the optimized presign path (`src/presign.rs`):

- one `SendMany(kd, ka, xb)` per party instead of two rounds,
- commitment checks `G*kd == KD`, `G*ka == K+A`, `G*xb == X+B` as unforgeable `check`,
- adversary may rush / drop / replay / tamper,
- fair OT/MTA rotation modeled as public coin `flip(sid)` both parties agree on.

Validate (requires `tamarin-prover`):

```sh
tamarin-prover --prove models/presign_single_round.spthy
```

Expected: `single_broadcast`, `roles_agree` verified; `tamper_detected`
shows tampering blocks `StDone` unless the check passes; `secrecy_needs_threshold`
captures that single shares do not leak `kd`.

`cargo test` also enforces the executable counterparts in
`tests/optimized.rs` (round counts) and `tests/properties.rs`
(proptest: triple relation, agreement, tamper-abort, rotation unbiased).
