//! Exhaustive laws of the decision combinators over a finite domain.
mod common;

use access_control::{
    most_specific, strictest_all, with_snapshot, Decision, Merge,
};
use common::{domain, same_up_to_rank, Mm, PlainYes, Rk, D};

#[test]
fn strictest_is_associative() {
    for a in domain() {
        for b in domain() {
            for c in domain() {
                assert_eq!(
                    a.strictest(b).strictest(c),
                    a.strictest(b.strictest(c)),
                    "{a:?} {b:?} {c:?}"
                );
            }
        }
    }
}

#[test]
fn most_permissive_is_associative() {
    for a in domain() {
        for b in domain() {
            for c in domain() {
                assert_eq!(
                    a.most_permissive(b).most_permissive(c),
                    a.most_permissive(b.most_permissive(c)),
                    "{a:?} {b:?} {c:?}"
                );
            }
        }
    }
}

#[test]
fn both_are_idempotent() {
    for a in domain() {
        assert_eq!(a.strictest(a), a);
        assert_eq!(a.most_permissive(a), a);
    }
}

#[test]
fn both_commute_up_to_rank() {
    for a in domain() {
        for b in domain() {
            assert!(same_up_to_rank(&a.strictest(b), &b.strictest(a)), "{a:?} {b:?}");
            assert!(
                same_up_to_rank(&a.most_permissive(b), &b.most_permissive(a)),
                "{a:?} {b:?}"
            );
        }
    }
}

#[test]
fn allow_is_strictest_identity_and_deny_absorbs() {
    for a in domain() {
        assert_eq!(D::Allow.strictest(a), a);
        assert_eq!(a.strictest(D::Allow), a);
    }
    for x in domain() {
        if !matches!(x, Decision::Deny(_)) {
            continue;
        }
        for y in domain() {
            if matches!(y, Decision::Deny(_)) {
                continue;
            }
            assert_eq!(x.strictest(y), x, "{x:?} {y:?}");
            assert_eq!(y.strictest(x), x, "{y:?} {x:?}");
        }
    }
}

#[test]
fn allow_absorbs_most_permissive() {
    for a in domain() {
        assert_eq!(D::Allow.most_permissive(a), D::Allow);
        assert_eq!(a.most_permissive(D::Allow), D::Allow);
    }
}

#[test]
fn first_wins_on_equal_rank_in_both() {
    assert_eq!(D::Deny(Rk::A0).strictest(D::Deny(Rk::B0)), D::Deny(Rk::A0));
    assert_eq!(D::Deny(Rk::B0).strictest(D::Deny(Rk::A0)), D::Deny(Rk::B0));
    assert_eq!(D::Deny(Rk::A0).most_permissive(D::Deny(Rk::B0)), D::Deny(Rk::A0));
    assert_eq!(D::Deny(Rk::B0).most_permissive(D::Deny(Rk::A0)), D::Deny(Rk::B0));
    let s: Decision<&'static str> = Decision::Deny("a").strictest(Decision::Deny("b"));
    assert_eq!(s, Decision::Deny("a"));
    let p: Decision<&'static str> = Decision::Deny("a").most_permissive(Decision::Deny("b"));
    assert_eq!(p, Decision::Deny("a"));
    let s: Decision<&'static str> = Decision::Deny("b").strictest(Decision::Deny("a"));
    assert_eq!(s, Decision::Deny("b"));
    let p: Decision<&'static str> = Decision::Deny("b").most_permissive(Decision::Deny("a"));
    assert_eq!(p, Decision::Deny("b"));
}

#[test]
fn higher_rank_wins_in_any_order() {
    for (x, y, want) in [
        (Rk::A0, Rk::D2, Rk::D2),
        (Rk::D2, Rk::A0, Rk::D2),
        (Rk::C1, Rk::D2, Rk::D2),
        (Rk::D2, Rk::C1, Rk::D2),
    ] {
        assert_eq!(D::Deny(x).strictest(D::Deny(y)), D::Deny(want));
        assert_eq!(D::Deny(x).most_permissive(D::Deny(y)), D::Deny(want));
    }
}

#[test]
fn ask_merges_in_both() {
    let t = D::Ask(PlainYes(true));
    let f = D::Ask(PlainYes(false));
    assert_eq!(t.strictest(f), D::Ask(PlainYes(false)));
    assert_eq!(f.strictest(t), D::Ask(PlainYes(false)));
    assert_eq!(t.strictest(t), D::Ask(PlainYes(true)));
    assert_eq!(t.most_permissive(f), D::Ask(PlainYes(false)));
    assert_eq!(f.most_permissive(t), D::Ask(PlainYes(false)));
    assert_eq!(t.most_permissive(t), D::Ask(PlainYes(true)));
}

#[test]
fn merge_laws_hold_for_unit_and_plain_yes() {
    let units = [()];
    for a in units {
        for b in units {
            assert_eq!(a.merge(b), b.merge(a));
            for c in units {
                assert_eq!(a.merge(b).merge(c), a.merge(b.merge(c)));
            }
        }
    }
    let yes = [PlainYes(true), PlainYes(false)];
    for a in yes {
        for b in yes {
            assert_eq!(a.merge(b), b.merge(a));
            for c in yes {
                assert_eq!(a.merge(b).merge(c), a.merge(b.merge(c)));
            }
        }
    }
}

fn permutations3<T: Copy>(x: [T; 3]) -> [[T; 3]; 6] {
    let [a, b, c] = x;
    [[a, b, c], [a, c, b], [b, a, c], [b, c, a], [c, a, b], [c, b, a]]
}

#[test]
fn strictest_all_is_a_fold_from_allow_and_order_free() {
    assert_eq!(strictest_all(Vec::<D>::new()), D::Allow);
    for a in domain() {
        for b in domain() {
            for c in domain() {
                let f = strictest_all([a, b, c]);
                assert_eq!(f, a.strictest(b).strictest(c), "{a:?} {b:?} {c:?}");
                for p in permutations3([a, b, c]) {
                    assert!(same_up_to_rank(&strictest_all(p), &f), "{p:?} vs {f:?}");
                }
            }
        }
    }
}

#[test]
fn ranked_reasons_never_depend_on_order() {
    type M = Decision<Mm>;
    let denies: [M; 3] = [
        Decision::Deny(Mm::Closed),
        Decision::Deny(Mm::Denied),
        Decision::Deny(Mm::NotFound),
    ];
    for order in permutations3(denies) {
        assert_eq!(strictest_all(order), Decision::Deny(Mm::NotFound), "{order:?}");
        assert_eq!(
            order[0].most_permissive(order[1]).most_permissive(order[2]),
            Decision::Deny(Mm::NotFound),
            "{order:?}"
        );
        // Allow inserted at each of the four positions.
        let [a, b, c] = order;
        for with_allow in [[M::Allow, a, b, c], [a, M::Allow, b, c], [a, b, M::Allow, c], [a, b, c, M::Allow]] {
            assert_eq!(
                strictest_all(with_allow),
                Decision::Deny(Mm::NotFound),
                "{with_allow:?}"
            );
        }
    }
}

#[test]
fn deny_on_ask_settles_ask_only() {
    for a in domain() {
        let s = a.deny_on_ask(Rk::C1);
        assert!(!matches!(s, Decision::Ask(_)), "{a:?}");
        assert_eq!(s.deny_on_ask(Rk::C1), s);
        if matches!(a, Decision::Ask(_)) {
            assert_eq!(s, D::Deny(Rk::C1));
        } else {
            assert_eq!(s, a);
        }
    }
}

#[test]
fn most_specific_max_key_then_strictest() {
    assert_eq!(most_specific(Vec::<(u8, D)>::new()), None);
    assert_eq!(
        most_specific([(1u8, D::Deny(Rk::A0)), (2, D::Allow)]),
        Some(D::Allow)
    );
    assert_eq!(
        most_specific([(2u8, D::Allow), (2, D::Deny(Rk::A0)), (1, D::Deny(Rk::D2))]),
        Some(D::Deny(Rk::A0))
    );
    // A tie on key and rank keeps the first.
    assert_eq!(
        most_specific([(2u8, D::Deny(Rk::A0)), (2, D::Deny(Rk::B0))]),
        Some(D::Deny(Rk::A0))
    );
    assert_eq!(
        most_specific([(2u8, D::Deny(Rk::B0)), (2, D::Deny(Rk::A0))]),
        Some(D::Deny(Rk::B0))
    );

    // Every 3-element keyed list drawn from domain x {1, 2}, in all 6 orders.
    let items: Vec<(u8, D)> = [1u8, 2]
        .into_iter()
        .flat_map(|k| domain().into_iter().map(move |d| (k, d)))
        .collect();
    for x in &items {
        for y in &items {
            for z in &items {
                let reference = most_specific([*x, *y, *z]).unwrap();
                // Expected: strictest over the entries with the maximum key.
                let max = x.0.max(y.0).max(z.0);
                let expected = [*x, *y, *z]
                    .into_iter()
                    .filter(|(k, _)| *k == max)
                    .map(|(_, d)| d)
                    .fold(D::Allow, |acc, d| acc.strictest(d));
                assert!(same_up_to_rank(&reference, &expected), "{x:?} {y:?} {z:?}");
                for p in permutations3([*x, *y, *z]) {
                    let got = most_specific(p).unwrap();
                    assert!(same_up_to_rank(&got, &reference), "{p:?}");
                }
            }
        }
    }
}

#[test]
fn missing_snapshot_denies_without_asking() {
    let called = std::cell::Cell::new(false);
    // The closure would allow "the owner"; it must never run.
    let d: D = with_snapshot(None::<&u8>, Rk::D2, |_| {
        called.set(true);
        D::Allow
    });
    assert_eq!(d, D::Deny(Rk::D2));
    assert!(!called.get());
    let d: D = with_snapshot(Some(&7u8), Rk::D2, |s| {
        if *s == 7 {
            D::Allow
        } else {
            D::Deny(Rk::A0)
        }
    });
    assert_eq!(d, D::Allow);
}

#[test]
fn an_empty_caller_cannot_exist() {
    assert!(access_control::Identity::new("").is_err());
}

#[test]
fn decision_is_copy_when_parts_are() {
    fn c<T: Copy>() {}
    c::<Decision<&'static str>>();
    c::<D>();
}
