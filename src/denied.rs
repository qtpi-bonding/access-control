//! `Denied<R>`: a refusal that carries its reason and forwards that reason's
//! coded-error facts unchanged.

use std::fmt;

use coded_error::{CodedError, ErrorClass, Overrides};

/// A refusal carrying the reason it was made. Its `Display` and its coded
/// error (code, class, type name, overrides) are those of the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Denied<R> {
    reason: R,
}

impl<R> Denied<R> {
    /// Wraps `reason` as a refusal.
    pub fn new(reason: R) -> Self {
        Self { reason }
    }

    /// Borrows the reason for this refusal.
    pub fn reason(&self) -> &R {
        &self.reason
    }

    /// Consumes the refusal and returns its reason.
    pub fn into_reason(self) -> R {
        self.reason
    }
}

impl<R: fmt::Display> fmt::Display for Denied<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.reason.fmt(f)
    }
}

impl<R: fmt::Debug + fmt::Display> std::error::Error for Denied<R> {}

impl<R: CodedError> CodedError for Denied<R> {
    fn code(&self) -> &'static str {
        self.reason.code()
    }

    fn class(&self) -> ErrorClass {
        self.reason.class()
    }

    fn type_name(&self) -> &'static str {
        self.reason.type_name()
    }

    fn overrides(&self) -> Overrides {
        self.reason.overrides()
    }
}
