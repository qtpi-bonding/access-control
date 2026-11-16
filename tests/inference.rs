//! Compiles = passes: the call shapes consumers write need only `Decision<R>`.
use access_control::{strictest_all, with_snapshot, Decision};

fn from_snapshot(s: Option<&u8>) -> Decision<&'static str> {
    with_snapshot(s, "missing", |_| Decision::Allow)
}

fn combined(rules: &[Decision<&'static str>]) -> Decision<&'static str> {
    strictest_all(rules.iter().copied()).deny_on_ask("ask")
}

#[test]
fn plain_call_shapes_infer() {
    let d: Decision<&'static str> = Decision::Deny("x").strictest(Decision::Allow);
    assert_eq!(d, Decision::Deny("x"));
    assert_eq!(from_snapshot(None), Decision::Deny("missing"));
    assert_eq!(from_snapshot(Some(&1)), Decision::Allow);
    assert_eq!(combined(&[]), Decision::Allow);
}

#[test]
fn most_permissive_and_most_specific_infer() {
    let d: Decision<&'static str> = Decision::Deny("x").most_permissive(Decision::Allow);
    assert_eq!(d, Decision::Allow);
    let m = access_control::most_specific([(1u8, Decision::Deny("x")), (2, Decision::Allow)]);
    let m: Option<Decision<&'static str>> = m;
    assert_eq!(m, Some(Decision::Allow));
}
