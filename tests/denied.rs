//! `Denied<R>` carries a reason and forwards its coded-error facts unchanged.

use std::fmt;

use access_control::Denied;
use coded_error::{CodedError, ErrorClass, Overrides};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    NotFound,
    Closed,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotFound => f.write_str("not found"),
            Refusal::Closed => f.write_str("closed"),
        }
    }
}

impl std::error::Error for Refusal {}

impl CodedError for Refusal {
    fn code(&self) -> &'static str {
        match self {
            Refusal::NotFound => "test.access.not_found",
            Refusal::Closed => "test.access.closed",
        }
    }
    fn class(&self) -> ErrorClass {
        ErrorClass::Logical
    }
    fn type_name(&self) -> &'static str {
        "Refusal"
    }
    fn overrides(&self) -> Overrides {
        match self {
            Refusal::NotFound => Overrides {
                http: Some(404),
                ..Overrides::NONE
            },
            Refusal::Closed => Overrides {
                http: Some(409),
                ..Overrides::NONE
            },
        }
    }
}

#[test]
fn denied_forwards_the_reason_code_per_variant() {
    for r in [Refusal::NotFound, Refusal::Closed] {
        let d = Denied::new(r);
        assert_eq!(coded_error::Facts::of(&d), coded_error::Facts::of(&r));
        assert_eq!(d.type_name(), r.type_name());
        assert_eq!(d.to_string(), r.to_string());
        assert_eq!(*d.reason(), r);
    }
}

#[test]
fn denied_is_a_boxable_error_for_plain_reasons() {
    let e: Box<dyn std::error::Error> = Box::new(Denied::new("closed"));
    assert_eq!(e.to_string(), "closed");
}
