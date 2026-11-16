//! Typed allow/deny/ask decisions with ranked reasons.

mod decision;
mod id;

pub use decision::{most_specific, strictest_all, with_snapshot, Decision, Merge, Reason};
pub use id::{EmptyId, Identity, ResourceRef};
