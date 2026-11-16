//! `Grant<V, P>` is minted only by `check`, owned, and re-checkable.

mod common;

use std::cell::Cell;
use std::fmt;

use access_control::{check, Decision, Grant, Identity, Policy, Reason, ResourceRef};
use coded_error::{CodedError, ErrorClass, Facts, Overrides};
use common::{id, res, Exact, Fixed, Manage, Message, Read, ReadOnly, Scope, Switch};

#[test]
fn allow_mints_a_grant_with_caller_resource_and_payload() {
    let p = Exact::new("agent-42", "res:1");
    let g = check::<Read, _>(&p, &id("agent-42"), &res("res:1")).unwrap();
    assert_eq!(g.caller(), &id("agent-42"));
    assert_eq!(g.resource(), &res("res:1"));
    assert_eq!(g.payload(), &Scope { floor: 7 });
    assert!(check::<Read, _>(&p, &id("agent-99"), &res("res:1")).is_err());
    assert!(check::<Read, _>(&p, &id("agent-42"), &res("res:2")).is_err());
}

#[test]
fn deny_returns_the_reason() {
    let e = check::<Read, _>(&Fixed(Decision::Deny("nope")), &id("a"), &res("r")).unwrap_err();
    assert_eq!(e.into_reason(), "nope");
}

#[test]
fn ask_is_refused_with_ask_reason() {
    let e = check::<Read, _>(&Fixed(Decision::Ask(())), &id("a"), &res("r")).unwrap_err();
    assert_eq!(e.into_reason(), "asked");
}

/// Allows, but cannot compute a payload.
struct NoFloor;

impl Policy<Read> for NoFloor {
    type Reason = &'static str;
    type Payload = Scope;
    fn decide(&self, _: &Identity, _: &ResourceRef) -> Decision<&'static str> {
        Decision::Allow
    }
    fn ask_reason(&self) -> &'static str {
        "asked"
    }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<Scope, &'static str> {
        Err("no floor")
    }
}

#[test]
fn failing_payload_refuses() {
    let e = check::<Read, _>(&NoFloor, &id("a"), &res("r")).unwrap_err();
    assert_eq!(e.into_reason(), "no floor");
}

#[test]
fn each_verb_consults_its_own_impl() {
    let p = ReadOnly;
    assert!(check::<Read, _>(&p, &id("a"), &res("r")).is_ok());
    let e = check::<Message, _>(&p, &id("a"), &res("r")).unwrap_err();
    assert_eq!(e.into_reason(), "read only");
}

#[test]
fn still_allowed_follows_the_policy() {
    let sw = Switch(Cell::new(Decision::Allow));
    let g = check::<Read, _>(&sw, &id("a"), &res("r")).unwrap();
    assert!(g.still_allowed(&sw));
    sw.0.set(Decision::Deny("revoked"));
    assert!(!g.still_allowed(&sw));
    sw.0.set(Decision::Ask(()));
    assert!(!g.still_allowed(&sw));
    sw.0.set(Decision::Allow);
    assert!(g.still_allowed(&sw));
}

#[test]
fn still_allowed_is_pure_over_the_passed_policy() {
    let allow = Fixed(Decision::Allow);
    let deny = Fixed(Decision::Deny("no"));
    let ask = Fixed(Decision::Ask(()));
    let g = check::<Read, _>(&allow, &id("a"), &res("r")).unwrap();
    // The answer follows whichever policy is passed, in any order, repeatedly;
    // the grant caches no decision.
    for _ in 0..3 {
        assert!(g.still_allowed(&allow));
        assert!(!g.still_allowed(&deny));
        assert!(!g.still_allowed(&ask));
        assert!(g.still_allowed(&allow));
    }
    // A grant minted under one policy is judged by a different one when asked.
    let exact = Exact::new("someone-else", "other");
    assert!(!g.still_allowed(&exact));
    // The grant itself is unchanged by all of this.
    assert_eq!(g.payload(), &Scope { floor: 7 });
    assert_eq!(g.caller(), &id("a"));
    assert_eq!(g.resource(), &res("r"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coded {
    NoFloor,
}

impl fmt::Display for Coded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no history floor")
    }
}

impl std::error::Error for Coded {}

impl Reason for Coded {}

impl CodedError for Coded {
    fn code(&self) -> &'static str {
        "test.access.no_floor"
    }
    fn class(&self) -> ErrorClass {
        ErrorClass::Logical
    }
    fn type_name(&self) -> &'static str {
        "Coded"
    }
    fn overrides(&self) -> Overrides {
        Overrides {
            http: Some(404),
            ..Overrides::NONE
        }
    }
}

struct CodedPayloadFails;

impl Policy<Read> for CodedPayloadFails {
    type Reason = Coded;
    type Payload = Scope;
    fn decide(&self, _: &Identity, _: &ResourceRef) -> Decision<Coded> {
        Decision::Allow
    }
    fn ask_reason(&self) -> Coded {
        Coded::NoFloor
    }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<Scope, Coded> {
        Err(Coded::NoFloor)
    }
}

#[test]
fn a_failing_payload_gives_the_old_code() {
    let e = check::<Read, _>(&CodedPayloadFails, &id("a"), &res("r")).unwrap_err();
    assert_eq!(*e.reason(), Coded::NoFloor);
    assert_eq!(e.code(), "test.access.no_floor");
    assert_eq!(e.code(), Coded::NoFloor.code());
    assert_eq!(Facts::of(&e), Facts::of(&Coded::NoFloor));
    assert_eq!(e.to_string(), Coded::NoFloor.to_string());
}

#[test]
fn grant_is_clone_send_sync_static() {
    fn t<T: Clone + Send + Sync + 'static>() {}
    t::<Grant<Read, Scope>>();
    t::<Grant<Manage, ()>>();

    let g = check::<Read, _>(&Fixed(Decision::Allow), &id("a"), &res("r")).unwrap();
    let held = std::sync::Arc::new(std::sync::Mutex::new(vec![g.clone()]));
    let h2 = held.clone();
    std::thread::spawn(move || assert_eq!(h2.lock().unwrap()[0].payload(), &Scope { floor: 7 }))
        .join()
        .unwrap();
    assert_eq!(held.lock().unwrap().len(), 1);
    assert_eq!(g.into_payload(), Scope { floor: 7 });
}

#[test]
fn debug_names_the_verb() {
    let g = check::<Read, _>(&Fixed(Decision::Allow), &id("a"), &res("r")).unwrap();
    let s = format!("{g:?}");
    assert!(s.contains("read"), "{s}");
    assert!(!s.contains("message"), "{s}");
}
