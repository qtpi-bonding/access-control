//! Shared helpers for the integration tests.
#![allow(dead_code)]

use access_control::{Identity, ResourceRef};

pub fn id(s: &str) -> Identity {
    Identity::new(s).unwrap()
}

pub fn res(s: &str) -> ResourceRef {
    ResourceRef::new(s).unwrap()
}

use access_control::{Decision, Merge, Reason};

/// Test reason with two distinct values at rank 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rk {
    A0,
    B0,
    C1,
    D2,
}

impl Reason for Rk {
    fn rank(&self) -> u8 {
        match self {
            Rk::A0 | Rk::B0 => 0,
            Rk::C1 => 1,
            Rk::D2 => 2,
        }
    }
}

/// Test `Merge` payload: logical AND.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlainYes(pub bool);

impl Merge for PlainYes {
    fn merge(self, other: Self) -> Self {
        PlainYes(self.0 && other.0)
    }
}

pub type D = Decision<Rk, PlainYes>;

/// Every value of `D` (seven values).
pub fn domain() -> Vec<D> {
    vec![
        Decision::Deny(Rk::A0),
        Decision::Deny(Rk::B0),
        Decision::Deny(Rk::C1),
        Decision::Deny(Rk::D2),
        Decision::Ask(PlainYes(true)),
        Decision::Ask(PlainYes(false)),
        Decision::Allow,
    ]
}

/// Equal variant; for `Deny`, equal reason rank; otherwise equal.
pub fn same_up_to_rank(x: &D, y: &D) -> bool {
    match (x, y) {
        (Decision::Deny(a), Decision::Deny(b)) => a.rank() == b.rank(),
        _ => x == y,
    }
}

/// Ranked reasons where the most hiding one has the highest rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mm {
    NotFound,
    Denied,
    Closed,
}

impl Reason for Mm {
    fn rank(&self) -> u8 {
        match self {
            Mm::NotFound => 2,
            Mm::Denied => 1,
            Mm::Closed => 0,
        }
    }
}

use access_control::{Policy, Verb};
use std::cell::Cell;

/// Verb: read.
pub struct Read;
/// Verb: message.
pub struct Message;
/// Verb: manage.
pub struct Manage;

impl Verb for Read {
    const NAME: &'static str = "read";
}
impl Verb for Message {
    const NAME: &'static str = "message";
}
impl Verb for Manage {
    const NAME: &'static str = "manage";
}

/// Test payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Scope {
    pub floor: u64,
}

/// Allows exactly one caller/resource pair for `Read`, payload `Scope { floor: 7 }`.
pub struct Exact {
    caller: Identity,
    resource: ResourceRef,
}

impl Exact {
    pub fn new(caller: &str, resource: &str) -> Self {
        Exact {
            caller: id(caller),
            resource: res(resource),
        }
    }
}

impl Policy<Read> for Exact {
    type Reason = &'static str;
    type Payload = Scope;
    fn decide(&self, caller: &Identity, resource: &ResourceRef) -> Decision<&'static str> {
        if *caller == self.caller && *resource == self.resource {
            Decision::Allow
        } else {
            Decision::Deny("not you")
        }
    }
    fn ask_reason(&self) -> &'static str {
        "asked"
    }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<Scope, &'static str> {
        Ok(Scope { floor: 7 })
    }
}

/// Always returns the given decision for `Read`; payload `Scope { floor: 7 }`.
pub struct Fixed(pub Decision<&'static str>);

impl Policy<Read> for Fixed {
    type Reason = &'static str;
    type Payload = Scope;
    fn decide(&self, _: &Identity, _: &ResourceRef) -> Decision<&'static str> {
        self.0
    }
    fn ask_reason(&self) -> &'static str {
        "asked"
    }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<Scope, &'static str> {
        Ok(Scope { floor: 7 })
    }
}

/// A `Read` policy whose decision can be changed after the fact.
pub struct Switch(pub Cell<Decision<&'static str>>);

impl Policy<Read> for Switch {
    type Reason = &'static str;
    type Payload = Scope;
    fn decide(&self, _: &Identity, _: &ResourceRef) -> Decision<&'static str> {
        self.0.get()
    }
    fn ask_reason(&self) -> &'static str {
        "asked"
    }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<Scope, &'static str> {
        Ok(Scope { floor: 7 })
    }
}

/// Allows `Read`, denies `Message`; does not implement `Manage`.
pub struct ReadOnly;

impl Policy<Read> for ReadOnly {
    type Reason = &'static str;
    type Payload = ();
    fn decide(&self, _: &Identity, _: &ResourceRef) -> Decision<&'static str> {
        Decision::Allow
    }
    fn ask_reason(&self) -> &'static str {
        "asked"
    }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<(), &'static str> {
        Ok(())
    }
}

impl Policy<Message> for ReadOnly {
    type Reason = &'static str;
    type Payload = ();
    fn decide(&self, _: &Identity, _: &ResourceRef) -> Decision<&'static str> {
        Decision::Deny("read only")
    }
    fn ask_reason(&self) -> &'static str {
        "asked"
    }
    fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<(), &'static str> {
        Ok(())
    }
}
