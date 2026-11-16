//! Typed allow/deny/ask decisions with ranked reasons.

mod grant;
mod decision;
mod denied;
mod id;

#[cfg(feature = "testing")]
pub mod testing;

pub use decision::{most_specific, strictest_all, with_snapshot, Decision, Merge, Reason};
pub use denied::Denied;
pub use grant::{check, Grant, Policy, Verb};
pub use id::{EmptyId, Identity, ResourceRef};
