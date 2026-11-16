//! Tests for the `testing` feature (`AllowWith`); built only with `--features testing`.

mod common;

use access_control::testing::AllowWith;
use access_control::{check, Decision, Policy};
use common::{id, res, Manage, Read, Scope};

#[test]
fn allow_with_mints_for_any_verb_with_the_payload() {
    let p = AllowWith(Scope { floor: 3 });
    assert_eq!(
        check::<Read, _>(&p, &id("a"), &res("r")).unwrap().payload(),
        &Scope { floor: 3 }
    );
    let g = check::<Manage, _>(&p, &id("a"), &res("r")).unwrap();
    assert!(g.still_allowed(&p));
}

#[test]
fn allow_with_decides_allow_and_asks_with_testing_ask() {
    let p = AllowWith(Scope { floor: 3 });
    assert_eq!(
        <AllowWith<Scope> as Policy<Read>>::decide(&p, &id("a"), &res("r")),
        Decision::Allow
    );
    assert_eq!(<AllowWith<Scope> as Policy<Read>>::ask_reason(&p), "testing.ask");
}
