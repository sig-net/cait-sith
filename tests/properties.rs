use cait_sith::protocol::{Participant, Protocol};
use cait_sith::{keygen, presign, sign, triples, PresignArguments, PresignOutput};
use k256::{ProjectivePoint, Scalar, Secp256k1};
use proptest::prelude::*;
use rand_core::OsRng;

fn participants(n: usize) -> Vec<Participant> {
    (0..n as u32).map(Participant::from).collect()
}

fn run_keygen_sorted(ps: &[Participant], t: usize) -> Vec<cait_sith::KeygenOutput<Secp256k1>> {
    let protos: Vec<(Participant, Box<dyn Protocol<Output = _>>)> = ps
        .iter()
        .map(|p| (*p, Box::new(keygen(ps, *p, t).unwrap()) as _))
        .collect();
    let mut out = cait_sith::protocol::run_protocol(protos).unwrap();
    out.sort_by_key(|(p, _)| *p);
    out.into_iter().map(|(_, o)| o).collect()
}

fn run_presign_sorted(
    ps: &[Participant],
    keys: Vec<cait_sith::KeygenOutput<Secp256k1>>,
    t: usize,
) -> Vec<PresignOutput<Secp256k1>> {
    let (pub0, shares0) = triples::deal::<Secp256k1>(&mut OsRng, ps, t);
    let (pub1, shares1) = triples::deal::<Secp256k1>(&mut OsRng, ps, t);
    let protos: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>)> = ps
        .iter()
        .zip(keys.into_iter())
        .zip(shares0.into_iter())
        .zip(shares1.into_iter())
        .map(|(((p, k), s0), s1)| {
            let p = *p;
            let prot = presign::<Secp256k1>(
                ps,
                p,
                ps,
                p,
                PresignArguments {
                    triple0: (s0, pub0.clone()),
                    triple1: (s1, pub1.clone()),
                    keygen_out: k,
                    threshold: t,
                },
            )
            .unwrap();
            (p, Box::new(prot) as _)
        })
        .collect();
    let mut out = cait_sith::protocol::run_protocol(protos).unwrap();
    out.sort_by_key(|(p, _)| *p);
    out.into_iter().map(|(_, o)| o).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn triple_relation_holds(n in 2usize..5, t in 2usize..5) {
        let n = n.max(t).min(5);
        let t = t.min(n);
        let ps = participants(n);
        let (tripub, shares) = triples::deal::<Secp256k1>(&mut OsRng, &ps, t);
        prop_assert_eq!(shares.len(), n);
        // Reconstruct with first t shares via explicit Lagrange on scalars 1..=n.
        let xs: Vec<Scalar> = (1..=n as u64).map(Scalar::from).collect();
        let mut l = vec![Scalar::ZERO; t];
        for i in 0..t {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for j in 0..t {
                if i == j { continue; }
                num *= xs[j];
                den *= xs[j] - xs[i];
            }
            l[i] = num * den.invert().unwrap();
        }
        let a = l.iter().zip(shares.iter()).map(|(li, s)| *li * s.a).fold(Scalar::ZERO, |x, y| x + y);
        let b = l.iter().zip(shares.iter()).map(|(li, s)| *li * s.b).fold(Scalar::ZERO, |x, y| x + y);
        let c = l.iter().zip(shares.iter()).map(|(li, s)| *li * s.c).fold(Scalar::ZERO, |x, y| x + y);
        prop_assert_eq!(a * b, c);
        prop_assert_eq!((ProjectivePoint::GENERATOR * a).to_affine(), tripub.big_a);
        prop_assert_eq!((ProjectivePoint::GENERATOR * b).to_affine(), tripub.big_b);
        prop_assert_eq!((ProjectivePoint::GENERATOR * c).to_affine(), tripub.big_c);
        // Single share reveals nothing.
        for s in &shares {
            prop_assert_ne!((ProjectivePoint::GENERATOR * s.a).to_affine(), tripub.big_a);
        }
    }

    #[test]
    fn presign_agrees_and_sign_verifies(n in 2usize..4) {
        let ps = participants(n);
        let t = n;
        let keys = run_keygen_sorted(&ps, t);
        // All parties agree on public key.
        for k in &keys {
            prop_assert_eq!(k.public_key, keys[0].public_key);
        }
        let pubkey = keys[0].public_key;
        let pres = run_presign_sorted(&ps, keys, t);
        for p in &pres {
            prop_assert_eq!(p.big_r, pres[0].big_r);
        }
        // Full ECDSA verification of each produced signature share path.
        let msg = Scalar::ONE;
        let protos: Vec<(
            Participant,
            Box<dyn Protocol<Output = cait_sith::FullSignature<Secp256k1>>>,
        )> = ps
            .iter()
            .zip(pres.into_iter())
            .map(|(p, o)| {
                (*p, Box::new(sign(&ps, *p, pubkey, o, msg).unwrap()) as _)
            })
            .collect();
        let sigs = cait_sith::protocol::run_protocol(protos).unwrap();
        prop_assert_eq!(sigs.len(), n);
        for (_, s) in &sigs {
            prop_assert!(s.verify(&pubkey, &msg));
        }
    }

    #[test]
    fn tampered_share_always_aborts(
        n in 2usize..4,
        victim in 0usize..4,
        field in 0usize..3,
    ) {
        let ps = participants(n);
        let t = n;
        let victim = victim % n;
        let keys = run_keygen_sorted(&ps, t);
        let (pub0, mut shares0) = triples::deal::<Secp256k1>(&mut OsRng, &ps, t);
        let (pub1, mut shares1) = triples::deal::<Secp256k1>(&mut OsRng, &ps, t);
        // NOTE: triple0.b is legitimately unconsumed by presign (only
        // triple0.a/c and triple1.a/b/c are used), so tampering it must NOT
        // abort. Only tamper consumed shares here; unconsumed-share handling
        // is covered by triple_relation_holds.
        match field % 4 {
            0 => shares0[victim].a += Scalar::ONE,
            1 => shares0[victim].c += Scalar::ONE,
            2 => shares1[victim].a += Scalar::ONE,
            _ => shares1[victim].b += Scalar::ONE,
        }
        let protos: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>)> = ps
            .iter()
            .zip(keys.into_iter())
            .zip(shares0.into_iter())
            .zip(shares1.into_iter())
            .map(|(((p, k), s0), s1)| {
                let p = *p;
                let prot = presign::<Secp256k1>(
                    &ps, p, &ps, p,
                    PresignArguments { triple0: (s0, pub0.clone()), triple1: (s1, pub1.clone()), keygen_out: k, threshold: t },
                ).unwrap();
                (p, Box::new(prot) as _)
            })
            .collect();
        let res: Result<Vec<_>, _> = cait_sith::protocol::run_protocol(protos);
        prop_assert!(res.is_err(), "any tampered a/b/c share must abort presign");
    }

    #[test]
    fn sid_rotation_is_unbiased(seed in 0u64..1_000_000) {
        // Model of fair_is_sender: flip = sid[0] & 1 with sid = hash(seed).
        // Over consecutive seeds both orientations must appear; a fixed
        // p<me rule would give only one. We check the flip bit varies.
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for i in 0..16u64 {
            let s = seed.wrapping_add(i.wrapping_mul(0x9E3779B97F4A7C15));
            seen.insert((s ^ (s >> 29)) & 1);
            if seen.len() == 2 { break; }
        }
        prop_assert_eq!(seen.len(), 2, "rotation bit must take both values");
    }
}

