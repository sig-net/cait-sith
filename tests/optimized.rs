use cait_sith::protocol::{Action, Participant, Protocol};
use cait_sith::{keygen, presign, sign, triples, KeygenOutput, PresignArguments, PresignOutput};
use k256::{ProjectivePoint, Scalar, Secp256k1};
use rand_core::OsRng;
use std::collections::HashMap;

#[derive(Default)]
struct Counts {
    send_many: usize,
    send_private: usize,
    bytes_sent: usize,
}

fn drive<T>(mut ps: Vec<(Participant, Box<dyn Protocol<Output = T>>)>) -> HashMap<Participant, Counts>
where
    T: Send + 'static,
{
    let indices: HashMap<Participant, usize> =
        ps.iter().enumerate().map(|(i, (p, _))| (*p, i)).collect();
    let mut counts: HashMap<Participant, Counts> =
        ps.iter().map(|(p, _)| (*p, Counts::default())).collect();
    let size = ps.len();
    let mut done = vec![false; size];
    let mut remaining = size;
    while remaining > 0 {
        for i in 0..size {
            if done[i] {
                continue;
            }
            loop {
                let action = ps[i].1.poke().expect("poke");
                match action {
                    Action::Wait => break,
                    Action::SendMany(m) => {
                        let c = counts.get_mut(&ps[i].0).unwrap();
                        c.send_many += 1;
                        c.bytes_sent += m.len() * (size - 1);
                        for j in 0..size {
                            if i == j {
                                continue;
                            }
                            let from = ps[i].0;
                            ps[j].1.message(from, m.clone());
                        }
                    }
                    Action::SendPrivate(to, m) => {
                        let c = counts.get_mut(&ps[i].0).unwrap();
                        c.send_private += 1;
                        c.bytes_sent += m.len();
                        let from = ps[i].0;
                        ps[indices[&to]].1.message(from, m);
                    }
                    Action::Return(_) => {
                        done[i] = true;
                        remaining -= 1;
                        break;
                    }
                }
            }
        }
    }
    counts
}

#[test]
fn presign_is_single_round_broadcast() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let t = 3;
    let keygen_out = {
        let ps: Vec<(Participant, Box<dyn Protocol<Output = _>>)> = participants
            .iter()
            .map(|p| (*p, Box::new(keygen(&participants, *p, t).unwrap()) as _))
            .collect();
        let mut out = cait_sith::protocol::run_protocol(ps).unwrap();
        out.sort_by_key(|(p, _)| *p);
        out.into_iter().map(|(_, o)| o).collect::<Vec<_>>()
    };
    let (pub0, shares0) = triples::deal::<Secp256k1>(&mut OsRng, &participants, t);
    let (pub1, shares1) = triples::deal::<Secp256k1>(&mut OsRng, &participants, t);
    let ps: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>)> =
        participants
            .iter()
            .zip(keygen_out.into_iter())
            .zip(shares0.into_iter())
            .zip(shares1.into_iter())
            .map(|(((p, k), s0), s1)| {
                let p = *p;
                let prot = presign::<Secp256k1>(
                    &participants,
                    p,
                    &participants,
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
    let counts = drive(ps);
    for (p, c) in &counts {
        assert_eq!(c.send_many, 1, "presign must send exactly 1 broadcast ({p:?})");
        assert_eq!(c.send_private, 0, "presign must send no private messages");
        assert!(c.bytes_sent < 512, "presign broadcast must stay small");
    }
}

#[test]
fn sign_is_single_round_and_verifies() {
    let participants = vec![Participant::from(0u32), Participant::from(1u32)];
    let t = 2;
    let keygen_out: Vec<KeygenOutput<Secp256k1>> = {
        let ps: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>)> =
            participants
                .iter()
                .map(|p| (*p, Box::new(keygen(&participants, *p, t).unwrap()) as _))
                .collect();
        let mut out = cait_sith::protocol::run_protocol(ps).unwrap();
        out.sort_by_key(|(p, _)| *p);
        out.into_iter().map(|(_, o)| o).collect::<Vec<_>>()
    };
    let public_key = keygen_out[0].public_key;
    let (pub0, shares0) = triples::deal::<Secp256k1>(&mut OsRng, &participants, t);
    let (pub1, shares1) = triples::deal::<Secp256k1>(&mut OsRng, &participants, t);
    let pres: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>)> =
        participants
            .iter()
            .zip(keygen_out.into_iter())
            .zip(shares0.into_iter())
            .zip(shares1.into_iter())
            .map(|(((p, k), s0), s1)| {
                let p = *p;
                let prot = presign::<Secp256k1>(
                    &participants,
                    p,
                    &participants,
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
    let pres_out = cait_sith::protocol::run_protocol(pres).unwrap();
    let msg = Scalar::ONE;
    let ps: Vec<(Participant, Box<dyn Protocol<Output = _>>)> = pres_out
        .into_iter()
        .map(|(p, o)| (p, Box::new(sign(&participants, p, public_key, o, msg).unwrap()) as _))
        .collect();
    let counts = drive(ps);
    for (_, c) in &counts {
        assert_eq!(c.send_many, 1);
        assert_eq!(c.send_private, 0);
    }
}

#[test]
fn triple_shares_do_not_leak_secret() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let t = 3;
    let (tripub, shares) = triples::deal::<Secp256k1>(&mut OsRng, &participants, t);
    assert_eq!(shares.len(), 3);
    for s in &shares {
        let a_pub = (ProjectivePoint::GENERATOR * s.a).to_affine();
        assert_ne!(a_pub, tripub.big_a, "single share must not reveal secret");
    }
    // Lagrange at zero for scalars 1,2,3: L = [3, -3, 1]
    let l0 = Scalar::from(3u64);
    let l1 = -Scalar::from(3u64);
    let l2 = Scalar::ONE;
    let a = l0 * shares[0].a + l1 * shares[1].a + l2 * shares[2].a;
    let b = l0 * shares[0].b + l1 * shares[1].b + l2 * shares[2].b;
    let c = l0 * shares[0].c + l1 * shares[1].c + l2 * shares[2].c;
    assert_eq!(a * b, c, "triple relation must hold");
    assert_eq!(
        (ProjectivePoint::GENERATOR * a).to_affine(),
        tripub.big_a
    );
    assert_eq!(
        (ProjectivePoint::GENERATOR * b).to_affine(),
        tripub.big_b
    );
    assert_eq!(
        (ProjectivePoint::GENERATOR * c).to_affine(),
        tripub.big_c
    );
}

#[test]
fn tampered_triple_share_fails_presign() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let t = 3;
    let keygen_out = {
        let ps: Vec<(Participant, Box<dyn Protocol<Output = _>>)> = participants
            .iter()
            .map(|p| (*p, Box::new(keygen(&participants, *p, t).unwrap()) as _))
            .collect();
        let mut out = cait_sith::protocol::run_protocol(ps).unwrap();
        out.sort_by_key(|(p, _)| *p);
        out.into_iter().map(|(_, o)| o).collect::<Vec<_>>()
    };
    let (pub0, mut shares0) = triples::deal::<Secp256k1>(&mut OsRng, &participants, t);
    let (pub1, shares1) = triples::deal::<Secp256k1>(&mut OsRng, &participants, t);
    shares0[0].a += Scalar::ONE;
    let ps: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>)> =
        participants
            .iter()
            .zip(keygen_out.into_iter())
            .zip(shares0.into_iter())
            .zip(shares1.into_iter())
            .map(|(((p, k), s0), s1)| {
                let p = *p;
                let prot = presign::<Secp256k1>(
                    &participants,
                    p,
                    &participants,
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
    let res: Result<Vec<_>, _> = cait_sith::protocol::run_protocol(ps);
    assert!(res.is_err(), "tampered share must cause presign failure");
}

#[test]
fn triple_generation_fairness_over_many_runs() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let t = 3;
    let mut per_party_totals: HashMap<Participant, usize> =
        participants.iter().map(|p| (*p, 0usize)).collect();
    let runs = 6;
    for _ in 0..runs {
        let ps: Vec<(
            Participant,
            Box<dyn Protocol<Output = (triples::TripleShare<Secp256k1>, triples::TriplePub<Secp256k1>)>>,
        )> = participants
            .iter()
            .map(|p| {
                (
                    *p,
                    Box::new(triples::generate_triple::<Secp256k1>(&participants, *p, t).unwrap())
                        as _,
                )
            })
            .collect();
        let counts = drive(ps);
        for (p, c) in counts {
            *per_party_totals.get_mut(&p).unwrap() += c.bytes_sent;
        }
    }
    let max = *per_party_totals.values().max().unwrap() as f64;
    let min = *per_party_totals.values().min().unwrap() as f64;
    let ratio = max / min.max(1.0);
    assert!(
        ratio < 2.0,
        "triple-gen load must be fair across parties, ratio={ratio:.2} totals={per_party_totals:?}"
    );
}
