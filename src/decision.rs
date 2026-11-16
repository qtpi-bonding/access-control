//! Decision values, ranked reasons and the combinators over them.
//!
//! A [`Decision`] is one of three outcomes: `Deny` with a reason, `Ask`
//! with a payload that must be settled before use, or `Allow`. Reasons are
//! ranked by [`Reason::rank`] so that combining two denials never depends on
//! evaluation order. Asks are merged with [`Merge`].

/// A reason for a denial. When two denials meet, the one with the higher
/// rank wins; on equal rank the first one is kept.
pub trait Reason {
    /// The rank of this reason. Higher ranks win a `Deny`/`Deny` combination.
    fn rank(&self) -> u8 {
        0
    }
}

impl Reason for &'static str {}

/// Combines the payloads of two `Ask` decisions. Laws: associative and
/// commutative.
pub trait Merge {
    /// Merges `self` with `other`.
    fn merge(self, other: Self) -> Self;
}

impl Merge for () {
    fn merge(self, _: ()) {}
}

/// The outcome of a decision: denied with a reason, asking for a payload
/// `A` to be settled, or allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision<R, A = ()> {
    /// Refused, with the reason.
    Deny(R),
    /// Undetermined; the payload must be settled by the caller.
    Ask(A),
    /// Permitted.
    Allow,
}

impl<R: Reason, A: Merge> Decision<R, A> {
    /// The strictness rank: `Deny` is 0, `Ask` is 1, `Allow` is 2.
    pub fn rank(&self) -> u8 {
        match self {
            Decision::Deny(_) => 0,
            Decision::Ask(_) => 1,
            Decision::Allow => 2,
        }
    }

    /// The stricter of `self` and `other`.
    pub fn strictest(self, other: Self) -> Self {
        match (self, other) {
            (Decision::Deny(a), Decision::Deny(b)) => Self::deny_pair(a, b),
            (Decision::Ask(a), Decision::Ask(b)) => Decision::Ask(a.merge(b)),
            (a, b) if b.rank() < a.rank() => b,
            (a, _) => a,
        }
    }

    /// The more permissive of `self` and `other`.
    pub fn most_permissive(self, other: Self) -> Self {
        match (self, other) {
            (Decision::Deny(a), Decision::Deny(b)) => Self::deny_pair(a, b),
            (Decision::Ask(a), Decision::Ask(b)) => Decision::Ask(a.merge(b)),
            (a, b) if b.rank() > a.rank() => b,
            (a, _) => a,
        }
    }

    /// Replaces an `Ask` with `Deny(reason)`; other decisions are unchanged.
    pub fn deny_on_ask(self, reason: R) -> Self {
        match self {
            Decision::Ask(_) => Decision::Deny(reason),
            other => other,
        }
    }

    /// Shared `Deny`/`Deny` rule: the higher rank wins, equal rank keeps `a`.
    fn deny_pair(a: R, b: R) -> Self {
        if b.rank() > a.rank() {
            Decision::Deny(b)
        } else {
            Decision::Deny(a)
        }
    }
}

/// The strictest of all decisions, folded from [`Decision::Allow`]. An empty
/// input yields `Allow`.
pub fn strictest_all<R: Reason, A: Merge>(
    ds: impl IntoIterator<Item = Decision<R, A>>,
) -> Decision<R, A> {
    ds.into_iter()
        .fold(Decision::Allow, |acc, d| acc.strictest(d))
}

/// Combines the decisions whose key is the greatest. A strictly greater key
/// replaces the current result; an equal key is combined with `strictest`.
/// An empty input yields `None`.
pub fn most_specific<K: Ord, R: Reason, A: Merge>(
    it: impl IntoIterator<Item = (K, Decision<R, A>)>,
) -> Option<Decision<R, A>> {
    let mut current: Option<(K, Decision<R, A>)> = None;
    for (key, decision) in it {
        current = Some(match current {
            None => (key, decision),
            Some((best, acc)) => {
                if key > best {
                    (key, decision)
                } else if key == best {
                    (best, acc.strictest(decision))
                } else {
                    (best, acc)
                }
            }
        });
    }
    current.map(|(_, d)| d)
}

/// Evaluates `decide` on the snapshot. A missing snapshot denies with
/// `missing` and never calls `decide` (fail closed).
pub fn with_snapshot<S: ?Sized, R, A>(
    snapshot: Option<&S>,
    missing: R,
    decide: impl FnOnce(&S) -> Decision<R, A>,
) -> Decision<R, A> {
    match snapshot {
        Some(s) => decide(s),
        None => Decision::Deny(missing),
    }
}
