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
