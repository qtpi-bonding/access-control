//! Without the `testing` feature the `testing` module does not exist.
#![cfg(not(feature = "testing"))]

#[test]
fn the_testing_module_needs_its_feature() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui_nofeature/*.rs");
}
