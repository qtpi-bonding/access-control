//! Test-only policies for code that consumes access-control.
//!
//! Tests only. Enable the `testing` feature only in `[dev-dependencies]`,
//! never in `[dependencies]`, so production builds cannot mint grants with
//! these policies.

use crate::decision::Decision;
use crate::grant::{Policy, Verb};
use crate::id::{Identity, ResourceRef};

/// Allows every caller, resource and verb, handing out a clone of the payload. Tests only.
#[derive(Debug, Clone)]
pub struct AllowWith<P>(pub P);

impl<V: Verb, P: Clone> Policy<V> for AllowWith<P> {
    type Reason = &'static str;
    type Payload = P;

    fn decide(&self, _caller: &Identity, _resource: &ResourceRef) -> Decision<Self::Reason> {
        Decision::Allow
    }

    fn ask_reason(&self) -> Self::Reason {
        "testing.ask"
    }

    fn payload(
        &self,
        _caller: &Identity,
        _resource: &ResourceRef,
    ) -> Result<Self::Payload, Self::Reason> {
        Ok(self.0.clone())
    }
}
