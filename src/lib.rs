//! Typed allow/deny/ask decisions with ranked reasons, and grants that only a
//! successful [`check`] can mint.
//!
//! # The model
//!
//! - **Decision.** A [`Decision<R, A>`] is `Deny(R)`, `Ask(A)` or `Allow`.
//!   `Deny` carries a reason, `Ask` carries a payload that must be settled
//!   before use, and `Allow` permits the action.
//! - **Ranked reasons.** Each [`Reason`] has a rank. When two denials meet,
//!   the one with the higher rank wins regardless of evaluation order. On an
//!   equal rank the first one is kept (first wins), in both [`strictest_all`]
//!   and the combinators on [`Decision`].
//! - **Asks are settled explicitly.** An `Ask` is never allowed implicitly.
//!   [`Decision::deny_on_ask`] turns it into a denial with a chosen reason.
//!   Within this crate, [`check`] and [`Grant::still_allowed`] are the only
//!   points where an `Ask` is settled: `check` refuses it with the policy's
//!   [`Policy::ask_reason`], and `still_allowed` treats it as not allowed.
//! - **Fail-closed snapshots.** [`with_snapshot`] evaluates a decision over an
//!   optional snapshot. A missing snapshot denies with the given reason and
//!   never calls the closure.
//! - **Grants prove a `Policy` said yes.** A [`Grant<V, P>`] is an owned proof
//!   that a [`Policy`] for `V` allowed a caller to perform that [`Verb`] on a
//!   resource. It has no public constructor and no `Default`: outside
//!   [`check`] it is unforgeable, but any [`Policy`] in scope that is
//!   implemented for `V` can mint one through [`check`], and
//!   [`crate::testing::AllowWith`] can mint a grant for any `V` when the
//!   `testing` feature is enabled. Keep your [`Verb`] types `pub(crate)` so
//!   that only your own policy can implement [`Policy`] for them.
//! - **No caching.** [`Grant::still_allowed`] asks the policy it is given,
//!   afresh, every time. It is pure over that policy, and the grant stores no
//!   decision of its own.
//!
//! # Example
//!
//! A local verb and a policy that allows one caller. [`check`] mints a
//! [`Grant`] for that caller and refuses everyone else.
//!
//! ```
//! use access_control::{check, Decision, Identity, Policy, ResourceRef, Verb};
//!
//! struct Read;
//! impl Verb for Read {
//!     const NAME: &'static str = "read";
//! }
//!
//! struct OwnerOnly;
//! impl Policy<Read> for OwnerOnly {
//!     type Reason = &'static str;
//!     type Payload = ();
//!
//!     fn decide(&self, caller: &Identity, _resource: &ResourceRef) -> Decision<&'static str> {
//!         if caller.as_str() == "agent-1" {
//!             Decision::Allow
//!         } else {
//!             Decision::Deny("not the owner")
//!         }
//!     }
//!
//!     fn ask_reason(&self) -> &'static str {
//!         "asked"
//!     }
//!
//!     fn payload(&self, _: &Identity, _: &ResourceRef) -> Result<(), &'static str> {
//!         Ok(())
//!     }
//! }
//!
//! let policy = OwnerOnly;
//! let resource = ResourceRef::new("res:general")?;
//!
//! let grant = check::<Read, _>(&policy, &Identity::new("agent-1")?, &resource)?;
//! assert!(grant.still_allowed(&policy));
//!
//! let refused = check::<Read, _>(&policy, &Identity::new("agent-2")?, &resource);
//! assert_eq!(refused.unwrap_err().into_reason(), "not the owner");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Type inference
//!
//! Write `Decision<R>` once in a return type or binding; inference does not
//! fall back to the `()` default for the `Ask` payload. Use `Decision<R, A>`
//! when a payload is needed.

mod decision;
mod denied;
mod grant;
mod id;

#[cfg(feature = "testing")]
pub mod testing;

pub use decision::{most_specific, strictest_all, with_snapshot, Decision, Merge, Reason};
pub use denied::Denied;
pub use grant::{check, Grant, Policy, Verb};
pub use id::{EmptyId, Identity, ResourceRef};
