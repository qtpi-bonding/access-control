//! Parity of `Decision<&'static str, PlainYes>` with a verbatim copy of the
//! reference engine's decision type.
mod common;

use access_control::{Decision, Merge};
use common::PlainYes;

// Verbatim copy of `Decision` and its impl from structmux
// `structmux-policy/src/lib.rs` lines 13-46 at commit 91e5f897 (test-only oracle).
#[allow(dead_code)]
mod oracle {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Decision {
        Deny(&'static str),
        Ask { plain_yes: bool },
        Allow,
    }

    impl Decision {
        pub fn rank(self) -> u8 {
            match self {
                Self::Deny(_) => 0,
                Self::Ask { .. } => 1,
                Self::Allow => 2,
            }
        }
        pub fn strictest(self, other: Self) -> Self {
            match (self, other) {
                (Self::Ask { plain_yes: a }, Self::Ask { plain_yes: b }) => {
                    Self::Ask { plain_yes: a && b }
                }
                (a, b) if b.rank() < a.rank() => b,
                (a, _) => a,
            }
        }
        pub fn most_permissive(self, other: Self) -> Self {
            match (self, other) {
                (Self::Ask { plain_yes: a }, Self::Ask { plain_yes: b }) => {
                    Self::Ask { plain_yes: a && b }
                }
                (a, b) if b.rank() > a.rank() => b,
                (a, _) => a,
            }
        }
    }
}

type Mine = Decision<&'static str, PlainYes>;

fn grid() -> Vec<(oracle::Decision, Mine)> {
    vec![
        (oracle::Decision::Deny("a"), Decision::Deny("a")),
        (oracle::Decision::Deny("b"), Decision::Deny("b")),
        (
            oracle::Decision::Ask { plain_yes: true },
            Decision::Ask(PlainYes(true)),
        ),
        (
            oracle::Decision::Ask { plain_yes: false },
            Decision::Ask(PlainYes(false)),
        ),
        (oracle::Decision::Allow, Decision::Allow),
    ]
}

fn map(o: oracle::Decision) -> Mine {
    match o {
        oracle::Decision::Deny(s) => Decision::Deny(s),
        oracle::Decision::Ask { plain_yes } => Decision::Ask(PlainYes(plain_yes)),
        oracle::Decision::Allow => Decision::Allow,
    }
}

#[test]
fn strictest_agrees_with_the_oracle_on_the_full_grid() {
    for (ox, x) in grid() {
        for (oy, y) in grid() {
            assert_eq!(map(ox.strictest(oy)), x.strictest(y), "{ox:?} {oy:?}");
        }
    }
}

#[test]
fn most_permissive_agrees_with_the_oracle_on_the_full_grid() {
    for (ox, x) in grid() {
        for (oy, y) in grid() {
            assert_eq!(
                map(ox.most_permissive(oy)),
                x.most_permissive(y),
                "{ox:?} {oy:?}"
            );
        }
    }
}

#[test]
fn rank_agrees_with_the_oracle() {
    for (ox, x) in grid() {
        assert_eq!(ox.rank(), x.rank(), "{ox:?}");
    }
}

#[test]
fn plain_yes_merge_is_and() {
    assert_eq!(PlainYes(true).merge(PlainYes(false)), PlainYes(false));
}
