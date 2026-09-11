use std::path::PathBuf;

#[test]
fn tamarin_model_pins_security_lemmas() {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "models", "presign_single_round.spthy"]
        .iter()
        .collect();
    let model = std::fs::read_to_string(&path).expect("tamarin model must exist");
    for lemma in [
        "lemma single_broadcast",
        "lemma tamper_detected",
        "lemma roles_agree",
        "lemma secrecy_needs_threshold",
    ] {
        assert!(model.contains(lemma), "model missing {lemma}");
    }
    assert!(model.contains("SingleSend"), "model must bound one broadcast");
    assert!(model.contains("flip("), "model must cover rotation coin");
}
