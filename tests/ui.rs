//! Compile-fail cases: a `Grant` cannot be forged and verbs are checked.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
